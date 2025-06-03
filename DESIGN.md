# Design Documentation for Perimeter Host Check

This document outlines the design decisions, architecture, and implementation details of the Perimeter Host Check tool.

## Overview

Perimeter Host Check is a Python monitoring tool designed to automate the verification of network hosts for potential issues such as SSL certificate expiration, unreachable hosts, and network connectivity problems. The tool is meant to be run regularly (e.g., as a cron job) to provide early warnings for administrators before issues impact end users.

## Core Design Requirements

1. **Proactive Monitoring**: The tool must identify potential issues before they become critical.
2. **Automation Friendly**: The tool should be designed to run unattended in scheduled tasks.
3. **Customizable Alerting**: Administrators should be able to control warning thresholds and notification settings.
4. **Comprehensive Record Keeping**: The tool should maintain a history of checks for trending and analysis.
5. **Flexible Grouping**: Hosts should be organizable into logical groups for easier management.
6. **Portability**: The tool should work across different operating systems.
7. **Performance**: The tool should be able to check multiple hosts concurrently.
8. **Data Persistence**: Configuration and check history should be stored persistently.
9. **Data Portability**: Support for import/export of configuration data.

## Architecture

The application follows a modular design with clear separation of concerns:

### Configuration Management
- Config data is stored in JSON format for easy parsing and human readability
- Default configuration path is determined using the `platformdirs` library for cross-platform compatibility
- Automatic creation of minimal default configuration
- Configuration validation to ensure correctness

### Network & SSL Checking
- SSL certificate validation using the `cryptography` library
- Host availability checks via HTTP/HTTPS requests
- Network connectivity verification prior to host checks
- Certificate hostname validation with wildcard support

### Concurrency
- Parallel host checking using thread pools for efficient performance
- Configurable number of worker threads

### Data Import/Export
- CSV import/export for configuration management
- Timestamped backup capability

### User Interface
- Command-line interface with comprehensive options
- Organized output with tables grouped by host categories
- Relative time display for check history

## Key Components

### ConfigEntry Class
Represents a single host configuration entry with metadata including:
- URL
- Owner (contact information)
- Check history timestamps
- Comments
- Group assignment
- Ignore settings

### Host Checking Logic
- `check_single_host()`: Verifies a single host, checking both connectivity and SSL certificate status
- `check_hosts()`: Orchestrates parallel checking of multiple hosts
- Intelligent handling of redirects

### Timestamp Management
- UTC-standardized timestamps for consistent time handling
- Relative time display for improved readability
- Proper timezone handling

### Results Formatting
- Organized presentation in tables
- Grouping by host categories
- Separate display for successful checks and issues

## Design Decisions

### JSON vs Other Formats
JSON was chosen for configuration storage due to:
- Native Python support
- Human readability and editability
- Structured format for complex data

### Threading vs Asynchronous I/O
Threading was chosen over async I/O because:
- The application is I/O bound
- The target usage doesn't involve thousands of simultaneous connections
- Simpler implementation and maintenance
- Thread pool executor provides sufficient concurrency control

### Certificate Validation
The `cryptography` library was chosen for certificate validation because:
- It provides detailed access to certificate properties
- It offers more control than the standard `ssl` module alone
- It handles complex validations like Subject Alternative Name checking

### CSV for Data Exchange
CSV was chosen for import/export because:
- Universal compatibility
- Easy to edit in spreadsheet applications
- Simple structure for straightforward data

### User Notifications
- The primary output is console-based for integration with monitoring systems
- Future enhancement could include email or other notification methods

## Implementation Details

### Timestamp Handling
All timestamps are stored in ISO 8601 format with UTC timezone to avoid ambiguity and ensure consistency across different systems.

### Certificate Expiry Warnings
Configurable warning thresholds allow administrators to set how many days before expiration a certificate should trigger warnings, with a default of 20 days.

### Hostname Validation
The tool implements custom hostname matching logic to properly handle wildcards in certificates, such as `*.example.com`.

### Ignore Until Functionality
Hosts can be temporarily excluded from checks using the `ignore-until` feature, allowing administrators to suppress known issues for a specified period.

### Concurrent Host Checking
A thread pool is used to check multiple hosts simultaneously, with configurable worker count (default: 10).

## Future Enhancements

Potential areas for future development include:

1. **Email notifications**: Direct email alerts for critical issues
2. **Web interface**: A simple web dashboard for viewing status
3. **Historical data analysis**: Trend analysis of check results over time
4. **Integration with monitoring systems**: Support for Nagios, Prometheus, etc.
5. **Additional check types**: DNS resolution, HTTP status codes, response time, etc.
6. **Response content validation**: Checking for specific content in responses

## Performance Considerations

- Default thread pool size of 10 workers balances parallelism with resource usage
- Connection timeouts prevent hanging on unresponsive hosts
- URL validation ensures only valid targets are checked
- Network connectivity verification prevents unnecessary checks when network is down

## Security Considerations

- SSL verification can be disabled for troubleshooting but is recommended for production use
- The tool uses the system's certificate store for validation
- No sensitive data is stored in the configuration file

## Conclusion

The Perimeter Host Check tool is designed to be a reliable, efficient, and flexible solution for monitoring network perimeter hosts. Its modular architecture allows for easy maintenance and extension, while its focused feature set ensures it performs its core function effectively.
