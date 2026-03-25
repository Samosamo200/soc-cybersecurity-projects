import argparse
import sys
import random
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler


def generate_demo_data(n=2000):
    random.seed(42)
    np.random.seed(42)

    rows = []
    for _ in range(n):
        is_brute = random.random() < 0.35
        if is_brute:
            attempts = np.random.randint(10, 200)
            unique_users = np.random.randint(1, 5)
            time_window = np.random.uniform(1, 30)
            avg_interval = np.random.uniform(0.1, 3)
            success_rate = np.random.uniform(0.0, 0.05)
            label = 1
        else:
            attempts = np.random.randint(1, 10)
            unique_users = np.random.randint(1, 3)
            time_window = np.random.uniform(10, 300)
            avg_interval = np.random.uniform(5, 120)
            success_rate = np.random.uniform(0.5, 1.0)
            label = 0
        rows.append({
            'attempts': attempts,
            'unique_users': unique_users,
            'time_window_sec': time_window,
            'avg_interval_sec': avg_interval,
            'success_rate': success_rate,
            'label': label
        })
    return pd.DataFrame(rows)


def parse_log_file(filepath):
    import re
    from collections import defaultdict

    pattern = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+\s+'
        r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)'
    )
    success_pattern = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+\s+'
        r'Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)'
    )

    ip_data = defaultdict(lambda: {'failed': 0, 'success': 0, 'users': set(), 'times': []})

    def parse_time(month, day, time_str):
        from datetime import datetime
        months = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
                  'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
        h, m, s = time_str.split(':')
        return (months.get(month, 1) * 30 + int(day)) * 86400 + int(h) * 3600 + int(m) * 60 + int(s)

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            m = pattern.search(line)
            if m:
                ip = m.group('ip')
                ip_data[ip]['failed'] += 1
                ip_data[ip]['users'].add(m.group('user'))
                ip_data[ip]['times'].append(parse_time(m.group('month'), m.group('day'), m.group('time')))
            m = success_pattern.search(line)
            if m:
                ip_data[m.group('ip')]['success'] += 1

    rows = []
    for ip, d in ip_data.items():
        total = d['failed'] + d['success']
        if total == 0:
            continue
        times = sorted(d['times'])
        time_window = (times[-1] - times[0]) if len(times) > 1 else 1
        avg_interval = time_window / len(times) if len(times) > 1 else 999
        rows.append({
            'ip': ip,
            'attempts': d['failed'],
            'unique_users': len(d['users']),
            'time_window_sec': max(time_window, 1),
            'avg_interval_sec': avg_interval,
            'success_rate': d['success'] / total
        })
    return pd.DataFrame(rows)


def train_model(df):
    features = ['attempts', 'unique_users', 'time_window_sec', 'avg_interval_sec', 'success_rate']
    X = df[features]
    y = df['label']
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    print('\n=== Model Evaluation ===')
    print(classification_report(y_test, model.predict(X_test), target_names=['Normal', 'Brute Force']))
    return model, scaler


def predict_log(model, scaler, df):
    features = ['attempts', 'unique_users', 'time_window_sec', 'avg_interval_sec', 'success_rate']
    X = scaler.transform(df[features])
    preds = model.predict(X)
    df = df.copy()
    df['prediction'] = ['BRUTE_FORCE' if p == 1 else 'normal' for p in preds]
    flagged = df[df['prediction'] == 'BRUTE_FORCE']
    print(f'\n=== Brute Force Detection Results ===')
    print(f'Total IPs analyzed : {len(df)}')
    print(f'Flagged as attack  : {len(flagged)}')
    if not flagged.empty:
        print('\nFlagged IPs:')
        for _, row in flagged.iterrows():
            print(f"  {row['ip']:<20} attempts={int(row['attempts'])} users={int(row['unique_users'])} success_rate={row['success_rate']:.2f}")


def main():
    parser = argparse.ArgumentParser(description='Brute Force Detector using Logistic Regression')
    parser.add_argument('--demo', action='store_true', help='Train and evaluate on synthetic data')
    parser.add_argument('--file', help='Path to auth.log to analyze')
    args = parser.parse_args()

    if not args.demo and not args.file:
        parser.print_help()
        sys.exit(1)

    if args.demo:
        print('Generating synthetic training data...')
        df = generate_demo_data(2000)
        train_model(df)
    else:
        print('Parsing log file...')
        log_df = parse_log_file(args.file)
        if log_df.empty:
            print('No SSH events found in log file.')
            sys.exit(0)
        print('Training model on synthetic data...')
        train_df = generate_demo_data(2000)
        model, scaler = train_model(train_df)
        predict_log(model, scaler, log_df)


if __name__ == '__main__':
    main()
