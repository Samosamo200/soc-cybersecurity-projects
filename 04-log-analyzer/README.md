# 04 – Log Analyzer

A SOC tool for parsing and analyzing Linux authentication and system logs (`auth.log`, `syslog`).

## Features

- Parse `/var/log/auth.log` and `/var/log/syslog` (or custom log files)
- Detect failed login attempts and successful logins
- Identify top offending source IPs
- Highlight sudo usage and privilege escalation events
- Export results to CSV or JSON
- `--demo` flag generates synthetic log data for testing

## Usage

```bash
python3 analyzer.py --file /var/log/auth.log
python3 analyzer.py --file /var/log/syslog --output results.json
python3 analyzer.py --demo
python3 analyzer.py --demo --output report.csv
```

## Requirements

- Python 3.7+
- No external libraries required (uses only the standard library)

## Output

The tool prints a summary to the console and optionally saves results to CSV or JSON:

| Field | Description |
|-------|-------------|
| `timestamp` | Time of the log event |
| `event_type` | Type of event (failed_login, success_login, sudo, etc.) |
| `user` | Username involved |
| `source_ip` | Source IP address (if available) |
| `raw` | Original log line |

## Example Output

```
=== Log Analysis Summary ===
Total lines parsed : 1500
Failed logins      : 342
Successful logins  : 58
Sudo events        : 12

Top 5 source IPs (failed logins):
  192.168.1.101 : 87
  10.0.0.55     : 64
  172.16.0.23   : 51
  10.0.0.12     : 40
  192.168.0.200 : 35
```
