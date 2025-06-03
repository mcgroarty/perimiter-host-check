# perimiter-host-check

A Python monitoring tool that performs automated checks on network hosts to identify:
- SSL certificates that are about to expire
- Unreachable hosts and services
- Network connectivity issues

## Purpose

This script is designed to be run as a scheduled task (e.g., nightly cron job) to proactively monitor your network perimeter and alert administrators about potential issues before they impact users. It helps maintain a reliable and secure network infrastructure by providing early warnings for:

- SSL/TLS certificate expiration
- Host availability issues
- Connection problems

## Features

- Configurable warning thresholds for certificate expiration
- Email notifications for responsible parties
- Tracking of check history
- Support for hostname grouping and filtering
- CSV import/export capabilities
- Concurrent checking for faster execution

## Usage

```bash
python3 perimiter-host-check.py [options]
```

See the script documentation for available command-line options and configuration details.

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.
