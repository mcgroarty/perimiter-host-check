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
- CSV import/export capabilities with automated timestamped backups
- Concurrent checking for faster execution

## Usage

```bash
python3 perimiter-host-check.py [options]
```

### Common Options

- `-c, --config FILE`: Use an alternate config file instead of the default
- `-v, --verbose`: Enable verbose output
- `-w, --workers N`: Set the number of worker threads (default: 10)
- `-a, --add`: Add URLs to configuration without checking
- `-e, --edit`: Edit the configuration file
- `--export [FILE]`: Export config to CSV file (default: perimeter.csv)
- `-b, --backup`: Create a backup of the config with timestamp (format: export-YYYY-MM-DD-HH-MM-SS.csv)
- `--import [FILE]`: Import config from CSV file (overwrites current config)
- `--list [SUBSTRING]`: List URLs in the config, optionally filtered by substring

See the script's help (`--help`) for complete documentation of all options.

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.
