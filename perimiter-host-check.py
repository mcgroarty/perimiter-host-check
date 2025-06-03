#!/usr/bin/env python3

######################################################################
# perimiter-host-check.py
# 
# A monitoring tool that checks SSL/TLS certificates for expiration and
# verifies host availability across network perimeters. The script can
# be scheduled to run nightly, providing early warnings for expiring
# certificates and unreachable hosts. It maintains a configuration of
# hosts to monitor, tracks their check history, and reports issues with
# detailed information about certificate status and connectivity.
######################################################################

import sys
import os
import subprocess
import platform
import datetime
import urllib.parse
from typing import Dict, List, Optional
import ssl
import socket
import argparse
import json
import platformdirs
import requests
import concurrent.futures
import shutil
import csv  # for CSV import/export

# cryptography imports
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

######################################################################
# Global Configuration
######################################################################
# Default number of days before certificate expiry to show a warning
DEFAULT_CERT_WARNING_DAYS = 20

######################################################################
# Timestamp Helper Functions
######################################################################
def parse_timestamp(ts: str) -> datetime.datetime:
    """
    Parse a timestamp string and return a timezone-aware datetime in UTC.
    If the timestamp ends with 'Z', it is assumed to be UTC.
    Otherwise, if the parsed datetime is naive, it is assumed to be local time
    and is converted to UTC.
    """
    if ts.endswith('Z'):
        dt = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ')
        return dt.replace(tzinfo=datetime.timezone.utc)
    try:
        dt = datetime.datetime.fromisoformat(ts)
    except Exception as e:
        raise ValueError(f"Invalid timestamp format: {ts}") from e
    if dt.tzinfo is None:
        local_tz = datetime.datetime.now().astimezone().tzinfo
        dt = dt.replace(tzinfo=local_tz)
    return dt.astimezone(datetime.timezone.utc)

def format_utc_timestamp(dt: datetime.datetime) -> str:
    """
    Convert a datetime to a standard UTC timestamp string in the format
    'YYYY-MM-DDTHH:MM:SSZ'.
    """
    dt_utc = dt.astimezone(datetime.timezone.utc)
    return dt_utc.strftime('%Y-%m-%dT%H:%M:%SZ')

def fix_timestamp(ts: Optional[str]) -> Optional[str]:
    """
    Given a timestamp string (possibly naive), return a UTC timestamp string.
    If ts is empty or None, return it unchanged.
    """
    if not ts:
        return ts
    try:
        dt = parse_timestamp(ts)
        return format_utc_timestamp(dt)
    except Exception:
        return ts

def format_relative_time(timestamp_str: Optional[str], now: datetime.datetime) -> str:
    """
    Given a UTC timestamp string, compute the relative time difference from 'now'
    and return it as a string using days and hours (e.g., "2d 5h"). If the timestamp
    is missing or empty, returns "never".
    """
    if not timestamp_str:
        return "never"
    try:
        dt = parse_timestamp(timestamp_str)
        diff = now - dt
        days = diff.days
        hours = diff.seconds // 3600
        return f"{days}d {hours}h"
    except Exception:
        return timestamp_str

######################################################################
# Helper Functions
######################################################################
def hostname_matches(cert_hostname: str, requested_hostname: str) -> bool:
    """
    Determine if cert_hostname (which might be a wildcard like '*.example.com')
    matches requested_hostname (e.g., 'foo.example.com').

    Implements single-level wildcard logic:
      - '*.example.com' matches 'foo.example.com'
      - Does NOT match 'bar.foo.example.com'
      - Does NOT match 'example.com'
    """
    cert_hostname = cert_hostname.lower().strip()
    requested_hostname = requested_hostname.lower().strip()

    if cert_hostname.startswith('*.'):
        base_domain = cert_hostname[2:]
        if not requested_hostname.endswith("." + base_domain):
            return False
        requested_labels = requested_hostname.split('.')
        base_labels = base_domain.split('.')
        if len(requested_labels) != len(base_labels) + 1:
            return False
        return True
    else:
        return cert_hostname == requested_hostname

######################################################################
# ConfigEntry Class
######################################################################
class ConfigEntry:
    def __init__(self, url: str, owner: str, last_check: Optional[str],
                 last_successful_check: Optional[str], comment: str, group: Optional[str] = "",
                 ignore_until: Optional[str] = None):
        self.url = url
        self.owner = owner
        self.last_check = last_check
        self.last_successful_check = last_successful_check
        self.comment = comment
        self.group = group or ""
        self.ignore_until = ignore_until  # New field: skip checks until this UTC timestamp

    def to_dict(self) -> Dict:
        # Return keys in the order: url, group, owner, last_check, last_successful_check, comment, ignore_until
        return {
            "url": self.url,
            "group": self.group,
            "owner": self.owner,
            "last_check": self.last_check,
            "last_successful_check": self.last_successful_check,
            "comment": self.comment,
            "ignore_until": self.ignore_until
        }

    @staticmethod
    def from_dict(data: Dict) -> 'ConfigEntry':
        owner = data.get("owner") or data.get("email")
        if owner is None:
            raise ValueError("Missing 'owner' (or 'email') in configuration entry")
        return ConfigEntry(
            data["url"],
            owner,
            data.get("last_check"),
            data.get("last_successful_check"),
            data["comment"],
            data.get("group", ""),
            data.get("ignore_until")
        )

######################################################################
# Default Config Path
######################################################################
def get_default_config_path() -> str:
    """
    Return the user-specific default config path from platformdirs.
    """
    config_dir = platformdirs.user_config_dir("perimeter-host-check", "monitoring")
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, "config.json")

######################################################################
# Creating / Loading / Saving the Config
######################################################################
def create_default_config(config_path: str, verbose: bool = False) -> List[ConfigEntry]:
    """
    Create a minimal default configuration file with just one sample host.
    """
    if verbose:
        print(f"Creating new config file at: {config_path}")
        
    default_hosts = [
        ConfigEntry(
            "https://8.8.8.8",
            "nobody@example.com",
            None,
            None,
            "Sample department webserver",
            "",
            None
        )
    ]
    
    config_content = {
        "hosts": [entry.to_dict() for entry in default_hosts]
    }
    
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(config_content, f, indent=2)
    
    return default_hosts

def load_config(config_path: str, verbose: bool = False) -> List[ConfigEntry]:
    """
    Load and validate the configuration file (creating a default if none exists).
    For backward compatibility, any stored naive timestamps are converted
    to standard UTC timestamps.
    """
    if not os.path.exists(config_path):
        return create_default_config(config_path, verbose)
    
    if verbose:
        print(f"Loading config file from: {config_path}")
    
    try:
        with open(config_path, 'r') as f:
            config_data = json.load(f)
            
        if not isinstance(config_data, dict) or "hosts" not in config_data:
            raise ValueError("Invalid config format: missing 'hosts' section")
            
        entries = []
        for idx, host in enumerate(config_data["hosts"]):
            required_fields = ["url", "comment"]
            missing_fields = [field for field in required_fields if field not in host]
            if missing_fields:
                raise ValueError(
                    f"Host entry {idx + 1} missing required fields: {', '.join(missing_fields)}"
                )
            entry = ConfigEntry.from_dict(host)
            # Fix any stored timestamps to be UTC-standard.
            entry.last_check = fix_timestamp(entry.last_check)
            entry.last_successful_check = fix_timestamp(entry.last_successful_check)
            if entry.ignore_until:
                entry.ignore_until = fix_timestamp(entry.ignore_until)
            entries.append(entry)
        
        check_duplicate_urls(entries)
        return entries
            
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse config file: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

def save_config(config_path: str, entries: List[ConfigEntry]) -> None:
    """
    Save the updated configuration file.
    All timestamps are stored as standard UTC strings.
    """
    config_content = {
        "hosts": [entry.to_dict() for entry in entries]
    }
    with open(config_path, 'w') as f:
        json.dump(config_content, f, indent=2)

######################################################################
# Check for Duplicate URLs
######################################################################
def check_duplicate_urls(entries: List[ConfigEntry]) -> None:
    """
    Ensure no URL appears more than once in the configuration.
    """
    seen = {}
    for idx, entry in enumerate(entries):
        if entry.url in seen:
            print(f"Error: Duplicate URL found in configuration: {entry.url}")
            print(f"  First occurrence at entry {seen[entry.url] + 1}")
            print(f"  Duplicate at entry {idx + 1}")
            sys.exit(1)
        seen[entry.url] = idx

######################################################################
# URL Validation
######################################################################
def validate_urls(entries: List[ConfigEntry]) -> None:
    """
    Validate that all configured URLs use HTTP(S) and contain a valid hostname.
    """
    for entry in entries:
        parsed = urllib.parse.urlparse(entry.url)
        if parsed.scheme not in ('http', 'https'):
            print(f"Error: URL '{entry.url}' must use HTTP or HTTPS scheme")
            sys.exit(1)
        if not parsed.hostname:
            print(f"Error: URL '{entry.url}' is missing a hostname")
            sys.exit(1)

######################################################################
# Network and SSL Checking
######################################################################
def check_network_connectivity() -> None:
    """
    Verify network connectivity by pinging 8.8.8.8. Exits on failure.
    """
    ping_param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        subprocess.run(
            ["ping", ping_param, "1", "8.8.8.8"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
    except subprocess.CalledProcessError:
        print("Error: No network connectivity (cannot ping 8.8.8.8)")
        sys.exit(1)

def get_ssl_info(hostname: str, port: int = 443) -> Dict:
    """
    Retrieve SSL cert info using cryptography.
    Return dict with subject, issuer, expiry (as a UTC-aware datetime), sans,
    or 'error' on failure.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin)
                
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()

                if hasattr(cert, 'not_valid_after_utc'):
                    expiry_aware = cert.not_valid_after_utc
                else:
                    expiry_aware = cert.not_valid_after
                # Ensure expiry is UTC-aware:
                if expiry_aware.tzinfo is None:
                    expiry_utc = expiry_aware.replace(tzinfo=datetime.timezone.utc)
                else:
                    expiry_utc = expiry_aware.astimezone(datetime.timezone.utc)

                sans = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                    sans = san_ext.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    pass

                return {
                    "subject": subject,
                    "issuer": issuer,
                    "expiry": expiry_utc,
                    "sans": sans
                }
    except Exception as e:
        return {"error": str(e)}

######################################################################
# Host Checking Logic
######################################################################
def check_single_host(entry: ConfigEntry, now: datetime.datetime, verbose: bool, warning_days: int = DEFAULT_CERT_WARNING_DAYS) -> Dict:
    """
    Check a single host: perform a HEAD request, optionally check the SSL cert,
    and track errors/warnings.
    Timestamps are updated in UTC.
    """
    TIMEOUT = 15  # seconds
    
    result = {
        "url": entry.url,
        "group": entry.group,
        "owner": entry.owner,
        "last_successful_check": entry.last_successful_check,
        "warnings": [],
        "error": None,
        "redirect": False,
        "issuer": None,
        "redirect_url": None,
        "comment": entry.comment
    }
    
    if verbose:
        print(f"Checking {entry.url}...")
    
    entry.last_check = format_utc_timestamp(now)
    
    try:
        parsed_url = urllib.parse.urlparse(entry.url)
        response = requests.head(
            entry.url,
            allow_redirects=False,
            verify=False,
            timeout=TIMEOUT
        )
        
        if response.status_code in (301, 302, 303, 307, 308):
            result['redirect'] = True
            result['redirect_url'] = response.headers.get("Location")
        
        if parsed_url.scheme == 'https':
            ssl_info = get_ssl_info(parsed_url.hostname)
            if 'error' in ssl_info:
                result['warnings'].append(f"SSL certificate check failed: {ssl_info['error']}")
            else:
                expiry = ssl_info['expiry']
                days_to_expiry = (expiry - now).days
                result['issuer'] = ssl_info['issuer']

                if days_to_expiry < 0:
                    result['warnings'].append(
                        f"SSL certificate has expired ({format_utc_timestamp(expiry)})"
                    )
                elif days_to_expiry < warning_days:
                    result['warnings'].append(
                        f"SSL certificate expires in {days_to_expiry} days ({format_utc_timestamp(expiry)})"
                    )
                
                hostname_mismatch = True
                if ssl_info['sans']:
                    for san in ssl_info['sans']:
                        if hostname_matches(san, parsed_url.hostname):
                            hostname_mismatch = False
                            break
                else:
                    subject_str = ssl_info['subject']
                    components = [c.strip() for c in subject_str.split(',')]
                    for comp in components:
                        if comp.startswith("CN="):
                            cn_value = comp[3:].strip()
                            if hostname_matches(cn_value, parsed_url.hostname):
                                hostname_mismatch = False
                                break
                
                if hostname_mismatch:
                    result['warnings'].append(
                        "Certificate name does not match hostname (including wildcard check)"
                    )
        
        if not result['warnings'] and not result['error']:
            stamp = format_utc_timestamp(now)
            entry.last_successful_check = stamp
            result['last_successful_check'] = stamp

    except requests.exceptions.Timeout:
        result['error'] = f"Connection timed out after {TIMEOUT} seconds"
    except requests.exceptions.RequestException as e:
        result['error'] = str(e)
    
    return result

def check_hosts(entries: List[ConfigEntry], workers: int, verbose: bool = False, warning_days: int = DEFAULT_CERT_WARNING_DAYS) -> List[Dict]:
    """
    Check all hosts in parallel using a specified number of worker threads,
    updating last check timestamps.
    Skips hosts that have an ignore_until date in the future.
    Current time is obtained as UTC.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    results = []
    
    # Filter out entries that are being ignored (if ignore_until is in the future)
    valid_entries = []
    for entry in entries:
        if entry.ignore_until:
            try:
                ignore_dt = parse_timestamp(entry.ignore_until)
                if ignore_dt > now:
                    if verbose:
                        print(f"Skipping {entry.url} (ignored until {entry.ignore_until})")
                    continue
            except Exception:
                pass
        valid_entries.append(entry)
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures_map = {
            executor.submit(check_single_host, entry, now, verbose, warning_days): entry
            for entry in valid_entries
        }
        for f in concurrent.futures.as_completed(futures_map):
            results.append(f.result())
    
    return results

######################################################################
# Formatting the Results
######################################################################
def format_tables(results: List[Dict], verbose: bool) -> None:
    """
    Print output tables grouped by the 'group' field.
    Hosts with no group (empty string) are printed first,
    followed by hosts in each group in its own table.
    The 'Last Successful Check' column now displays a relative time
    (in days and hours) computed from UTC timestamps, or "never" if none.
    Dashed lines are printed between entries only in the issues tables.
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # Separate successes and issues.
    successes = []
    issues = []
    for r in results:
        if r['warnings'] or r['error']:
            issues.append(r)
        else:
            successes.append(r)

    def group_by(results_list: List[Dict]) -> Dict[str, List[Dict]]:
        groups = {}
        for r in results_list:
            grp = r.get("group", "").strip()
            groups.setdefault(grp, []).append(r)
        return groups

    success_groups = group_by(successes)
    issue_groups = group_by(issues)

    # Print successful checks grouped by group (no dashed lines between entries).
    if verbose and successes:
        print("\nSuccessful Checks:")
        # Print hosts with no group first.
        if "" in success_groups:
            print("-" * 80)
            print("Hosts with no group:")
            print("-" * 80)
            print(f"{'URL':<40} {'Last Successful Check':<26} {'Redirect':<14}")
            print("-" * 80)
            for s in success_groups[""]:
                redir_text = f"(redirects -> {s['redirect_url']})" if s['redirect'] else ""
                last_check_str = format_relative_time(s['last_successful_check'], now)
                print(f"{s['url']:<40} {last_check_str:<26} {redir_text:<14}")
            print("-" * 80)
        # Then print each non-empty group.
        for grp in sorted(g for g in success_groups if g != ""):
            print("-" * 80)
            print(f"Hosts in group '{grp}':")
            print("-" * 80)
            print(f"{'URL':<40} {'Last Successful Check':<26} {'Redirect':<14}")
            print("-" * 80)
            for s in success_groups[grp]:
                redir_text = f"(redirects -> {s['redirect_url']})" if s['redirect'] else ""
                last_check_str = format_relative_time(s['last_successful_check'], now)
                print(f"{s['url']:<40} {last_check_str:<26} {redir_text:<14}")
            print("-" * 80)

    # Print issues grouped by group (dashed lines between entries).
    if issues:
        print("\nIssues Found:")
        if "" in issue_groups:
            print("-" * 100)
            print("Issues for hosts with no group:")
            print("-" * 100)
            print(f"{'URL':<40} {'Last Successful Check':<26} {'Issues'}")
            print("-" * 100)
            for i in issue_groups[""]:
                last_check_str = format_relative_time(i['last_successful_check'], now)
                if i['error']:
                    print(f"{i['url']:<40} {last_check_str:<26} Error: {i['error']}")
                for w in i['warnings']:
                    print(f"{i['url']:<40} {last_check_str:<26} Warning: {w}")
                if i['issuer'] and (
                    any("SSL" in w for w in i['warnings']) or
                    (i['error'] and "SSL" in i['error'])
                ):
                    print(f"{'':<40} {'':<26} Issuer: {i['issuer']}")
                print(f"Owner: {i['owner']}  |  Purpose: {i['comment']}")
                print("-" * 100)
        for grp in sorted(g for g in issue_groups if g != ""):
            print("-" * 100)
            print(f"Issues for hosts in group '{grp}':")
            print("-" * 100)
            print(f"{'URL':<40} {'Last Successful Check':<26} {'Issues'}")
            print("-" * 100)
            for i in issue_groups[grp]:
                last_check_str = format_relative_time(i['last_successful_check'], now)
                if i['error']:
                    print(f"{i['url']:<40} {last_check_str:<26} Error: {i['error']}")
                for w in i['warnings']:
                    print(f"{i['url']:<40} {last_check_str:<26} Warning: {w}")
                if i['issuer'] and (
                    any("SSL" in w for w in i['warnings']) or
                    (i['error'] and "SSL" in i['error'])
                ):
                    print(f"{'':<40} {'':<26} Issuer: {i['issuer']}")
                print(f"Owner: {i['owner']}  |  Purpose: {i['comment']}")
                print("-" * 100)
    
    print()

######################################################################
# Adding URLs
######################################################################
def add_urls(config_path: str, urls: List[str], verbose: bool) -> None:
    """
    Add user-supplied URLs to the config.
    Defaults: owner="nobody@example.com", comment="no description", group=""
    """
    entries = load_config(config_path, verbose)
    existing_urls = {e.url for e in entries}

    for url in urls:
        if url in existing_urls:
            print(f"Error: URL already exists in configuration: {url}")
            sys.exit(1)

    for url in urls:
        entries.append(ConfigEntry(
            url=url,
            owner="nobody@example.com",
            last_check=None,
            last_successful_check=None,
            comment="no description",
            group="",
            ignore_until=None
        ))
    
    if verbose:
        print(f"Adding {len(urls)} new URL(s) to configuration")

    save_config(config_path, entries)

######################################################################
# Editing the Config
######################################################################
def edit_config(config_path: str, verbose: bool) -> None:
    """
    Edit the config in the user's chosen editor, or fallback to vi/emacs.
    Create the file if not present yet.
    """
    if not os.path.exists(config_path):
        create_default_config(config_path, verbose=verbose)

    editor = os.environ.get("EDITOR", "")
    if editor:
        cmd = editor
    else:
        for candidate in ("vi", "emacs"):
            if shutil.which(candidate):
                cmd = candidate
                break
        else:
            print("Error: No editor found. Set EDITOR or install vi/emacs.")
            sys.exit(1)

    if verbose:
        print(f"Opening config file with editor: {cmd}")

    try:
        subprocess.run([cmd, config_path], check=True)
    except subprocess.CalledProcessError:
        print("Error: The editor exited with an error.")
        sys.exit(1)

######################################################################
# CSV Export/Import Functions
######################################################################
def export_config_to_csv(config_path: str, filename: str, verbose: bool) -> None:
    """
    Export the current configuration to a CSV file.
    Defaults to 'perimeter.csv' if no filename is provided.
    Aborts if the file already exists.
    The CSV file will contain the following columns:
      url, group, owner, last_check, last_successful_check, comment, ignore_until
    """
    if os.path.exists(filename):
        print(f"Error: File '{filename}' already exists. Aborting export to avoid overwrite.")
        sys.exit(1)
    
    entries = load_config(config_path, verbose)
    fieldnames = ["url", "group", "owner", "last_check", "last_successful_check", "comment", "ignore_until"]
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                writer.writerow({
                    "url": entry.url,
                    "group": entry.group,
                    "owner": entry.owner,
                    "last_check": entry.last_check or "",
                    "last_successful_check": entry.last_successful_check or "",
                    "comment": entry.comment,
                    "ignore_until": entry.ignore_until or ""
                })
        print(f"Configuration successfully exported to '{filename}'.")
    except Exception as e:
        print(f"Error during export: {e}")
        sys.exit(1)

def import_config_from_csv(config_path: str, filename: str, verbose: bool) -> None:
    """
    Import configuration from a CSV file, overwriting the current config.
    The CSV file must have exactly these columns (in any order):
      url, group, owner, last_check, last_successful_check, comment, ignore_until
    Aborts if the CSV is malformed.
    Also fixes timestamps to be in standard UTC.
    """
    fieldnames_expected = {"url", "group", "owner", "last_check", "last_successful_check", "comment", "ignore_until"}
    new_entries = []
    try:
        with open(filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            if set(reader.fieldnames) != fieldnames_expected:
                print("Error: CSV file does not contain the required columns.")
                print(f"Expected columns: {', '.join(fieldnames_expected)}")
                sys.exit(1)
            for row in reader:
                url = row["url"].strip()
                group = row["group"].strip() if row["group"] is not None else ""
                owner = row["owner"].strip() or "nobody@example.com"
                last_check = fix_timestamp(row["last_check"].strip() or None)
                last_successful_check = fix_timestamp(row["last_successful_check"].strip() or None)
                comment = row["comment"].strip()
                ignore_until = row.get("ignore_until", "").strip() or None
                
                if not url or not comment:
                    print("Error: CSV file is malformed. 'url' and 'comment' are required fields.")
                    sys.exit(1)

                parsed = urllib.parse.urlparse(url)
                if parsed.scheme not in ("http", "https") or not parsed.hostname:
                    print(f"Error: CSV file contains invalid URL: {url}")
                    sys.exit(1)

                new_entries.append(ConfigEntry(url, owner, last_check, last_successful_check, comment, group, ignore_until))
        check_duplicate_urls(new_entries)
        save_config(config_path, new_entries)
        print(f"Configuration successfully imported from '{filename}'.")
    except FileNotFoundError:
        print(f"Error: CSV file '{filename}' not found.")
        sys.exit(1)
    except csv.Error as e:
        print(f"Error: Failed to parse CSV file: {e}")
        sys.exit(1)

######################################################################
# Main
######################################################################
def main():
    default_workers = 10
    epilog_text = (
        "You can override the default configuration file using '-c FILE'.\n"
        f"Default config file: {get_default_config_path()}\n"
        "If a config file doesn't exist yet, a minimal one is created automatically.\n"
        "See --help for more usage instructions.\n"
    )

    parser = argparse.ArgumentParser(
        description="Check connectivity to configured hosts",
        epilog=epilog_text
    )
    parser.add_argument(
        "-c", "--config",
        metavar="FILE",
        help="Use an alternate config file instead of the default."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=default_workers,
        help=f"Set the number of worker threads to use (default: {default_workers})"
    )
    parser.add_argument(
        "-a", "--add",
        action="store_true",
        help="Add URLs to configuration without checking"
    )
    parser.add_argument(
        "-e", "--edit",
        action="store_true",
        help="Edit the configuration file (EDITOR env var or vi/emacs)."
    )
    parser.add_argument(
        "--export",
        nargs="?",
        const="perimeter.csv",
        metavar="FILE",
        help="Export config to CSV file (default: perimeter.csv)"
    )
    parser.add_argument(
        "--import",
        dest="import_file",
        nargs="?",
        const="perimeter.csv",
        metavar="FILE",
        help="Import config from CSV file (overwrites current config)"
    )
    parser.add_argument(
        "--list",
        nargs="?",
        const="",
        metavar="SUBSTRING",
        help="List the URLs in the config. If SUBSTRING is provided, list only URLs that contain that substring."
    )
    parser.add_argument(
        "--ignore-error",
        nargs=2,
        metavar=("URL", "DAYS"),
        help="Ignore errors for the given URL for the specified number of days. "
             "The URL will be skipped until the ignore period elapses."
    )
    parser.add_argument(
        "--warning-days",
        type=int,
        default=DEFAULT_CERT_WARNING_DAYS,
        help=f"Number of days before certificate expiry to show a warning (default: {DEFAULT_CERT_WARNING_DAYS})"
    )
    parser.add_argument(
        "urls",
        nargs="*",
        help="One or more URLs to add when using -a"
    )

    args = parser.parse_args()

    if args.config:
        config_path = args.config
    else:
        config_path = get_default_config_path()

    if args.verbose:
        print(f"Using config file: {config_path}")

    # --list option: List URLs and exit.
    if args.list is not None:
        entries = load_config(config_path, args.verbose)
        substring = args.list
        for entry in entries:
            if substring == "" or substring in entry.url:
                print(entry.url)
        sys.exit(0)

    # --ignore-error option: Update ignore_until for a given URL.
    if args.ignore_error:
        url, days_str = args.ignore_error
        try:
            days = int(days_str)
        except ValueError:
            print("Error: DAYS must be an integer.")
            sys.exit(1)
        now = datetime.datetime.now(datetime.timezone.utc)
        ignore_dt = now + datetime.timedelta(days=days)
        ignore_until_str = format_utc_timestamp(ignore_dt)
        entries = load_config(config_path, args.verbose)
        found = False
        for entry in entries:
            if entry.url == url:
                entry.ignore_until = ignore_until_str
                found = True
                break
        if not found:
            print(f"Error: URL {url} not found in configuration.")
            sys.exit(1)
        save_config(config_path, entries)
        print(f"Ignoring errors for {url} until {ignore_until_str}")
        sys.exit(0)

    if args.edit:
        edit_config(config_path, args.verbose)
        sys.exit(0)

    if args.add:
        if not args.urls:
            print("Error: No URLs provided with -a option")
            sys.exit(1)
        add_urls(config_path, args.urls, args.verbose)
        sys.exit(0)

    if args.export is not None and args.import_file is not None:
        print("Error: Cannot use both --export and --import options simultaneously.")
        sys.exit(1)
    if args.export is not None:
        export_config_to_csv(config_path, args.export, args.verbose)
        sys.exit(0)
    if args.import_file is not None:
        import_config_from_csv(config_path, args.import_file, args.verbose)
        sys.exit(0)

    entries = load_config(config_path, args.verbose)
    validate_urls(entries)
    check_network_connectivity()
    results = check_hosts(entries, args.workers, args.verbose, args.warning_days)
    format_tables(results, args.verbose)

    if args.verbose:
        print(f"Saving updated config file to: {config_path}")
    save_config(config_path, entries)

if __name__ == "__main__":
    main()
