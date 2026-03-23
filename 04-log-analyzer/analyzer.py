import argparse
import re
import json
import csv
import random
import sys
from collections import Counter
from datetime import datetime, timedelta


FAILED_LOGIN_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+\s+'
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)'
)
SUCCESS_LOGIN_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+\s+'
    r'Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)'
)
SUDO_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sudo\[.*?\]:\s+'
    r'(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)'
)
INVALID_USER_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+\s+'
    r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)'
)


def parse_log_line(line):
    m = FAILED_LOGIN_PATTERN.search(line)
    if m:
        return {
            'timestamp': f"{m.group('month')} {m.group('day')} {m.group('time')}",
            'event_type': 'failed_login',
            'user': m.group('user'),
            'source_ip': m.group('ip'),
            'raw': line.strip()
        }
    m = SUCCESS_LOGIN_PATTERN.search(line)
    if m:
        return {
            'timestamp': f"{m.group('month')} {m.group('day')} {m.group('time')}",
            'event_type': 'success_login',
            'user': m.group('user'),
            'source_ip': m.group('ip'),
            'raw': line.strip()
        }
    m = SUDO_PATTERN.search(line)
    if m:
        return {
            'timestamp': f"{m.group('month')} {m.group('day')} {m.group('time')}",
            'event_type': 'sudo',
            'user': m.group('user'),
            'source_ip': '',
            'raw': line.strip()
        }
    m = INVALID_USER_PATTERN.search(line)
    if m:
        return {
            'timestamp': f"{m.group('month')} {m.group('day')} {m.group('time')}",
            'event_type': 'invalid_user',
            'user': m.group('user'),
            'source_ip': m.group('ip'),
            'raw': line.strip()
        }
    return None


def parse_file(filepath):
    events = []
    total = 0
    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            total += 1
            event = parse_log_line(line)
            if event:
                events.append(event)
    return events, total


def generate_demo_logs():
    random.seed(42)
    ips = ['192.168.1.101', '10.0.0.55', '172.16.0.23', '10.0.0.12', '192.168.0.200', '203.0.113.5']
    users = ['root', 'admin', 'ubuntu', 'deploy', 'test', 'guest']
    valid_users = ['alice', 'bob', 'charlie']
    lines = []

    base = datetime(2026, 3, 1, 0, 0, 0)
    for i in range(1500):
        ts = base + timedelta(seconds=random.randint(0, 86400 * 60))
        stamp = ts.strftime('%b %d %H:%M:%S')
        r = random.random()
        if r < 0.23:
            user = random.choice(users)
            ip = random.choice(ips)
            lines.append(f'{stamp} server sshd[1234]: Failed password for {user} from {ip} port 22 ssh2')
        elif r < 0.27:
            user = random.choice(valid_users)
            ip = random.choice(ips[-2:])
            lines.append(f'{stamp} server sshd[1234]: Accepted publickey for {user} from {ip} port 22 ssh2')
        elif r < 0.285:
            user = random.choice(valid_users)
            lines.append(f'{stamp} server sudo[5678]:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash')
        elif r < 0.30:
            user = random.choice(users)
            ip = random.choice(ips)
            lines.append(f'{stamp} server sshd[1234]: Invalid user {user} from {ip} port 22')
        else:
            lines.append(f'{stamp} server kernel: random system message {i}')

    return lines


def print_summary(events, total_lines):
    by_type = Counter(e['event_type'] for e in events)
    failed = [e for e in events if e['event_type'] == 'failed_login']
    ip_counts = Counter(e['source_ip'] for e in failed if e['source_ip'])

    print('\n=== Log Analysis Summary ===')
    print(f'Total lines parsed : {total_lines}')
    print(f'Failed logins      : {by_type.get("failed_login", 0)}')
    print(f'Successful logins  : {by_type.get("success_login", 0)}')
    print(f'Sudo events        : {by_type.get("sudo", 0)}')
    print(f'Invalid users      : {by_type.get("invalid_user", 0)}')

    if ip_counts:
        print('\nTop 5 source IPs (failed logins):')
        for ip, count in ip_counts.most_common(5):
            print(f'  {ip:<20}: {count}')


def save_output(events, output_path):
    if output_path.endswith('.json'):
        with open(output_path, 'w') as f:
            json.dump(events, f, indent=2)
    else:
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'event_type', 'user', 'source_ip', 'raw'])
            writer.writeheader()
            writer.writerows(events)
    print(f'\nResults saved to: {output_path}')


def main():
    parser = argparse.ArgumentParser(description='SOC Log Analyzer - parse auth.log/syslog')
    parser.add_argument('--file', help='Path to log file')
    parser.add_argument('--demo', action='store_true', help='Use synthetic demo data')
    parser.add_argument('--output', help='Output file path (.csv or .json)')
    args = parser.parse_args()

    if not args.demo and not args.file:
        parser.print_help()
        sys.exit(1)

    if args.demo:
        lines = generate_demo_logs()
        events = []
        for line in lines:
            event = parse_log_line(line)
            if event:
                events.append(event)
        total = len(lines)
    else:
        events, total = parse_file(args.file)

    print_summary(events, total)

    if args.output:
        save_output(events, args.output)


if __name__ == '__main__':
    main()
