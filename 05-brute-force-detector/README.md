# 05 – Brute Force Detector

A machine learning tool that detects SSH brute-force attacks from log files using Logistic Regression.

## Features

- Trains on synthetic data representing normal vs. brute-force SSH behavior
- Analyzes real `auth.log` files and flags suspicious IPs
- Features used: attempt count, unique usernames, time window, average interval between attempts, success rate
- `--demo` flag trains and evaluates on synthetic data only

## Usage

```bash
python3 detector.py --demo
python3 detector.py --file /var/log/auth.log
```

## Requirements

```
scikit-learn
pandas
numpy
```

Install with:
```bash
pip install scikit-learn pandas numpy
```

## Features Explained

| Feature | Description |
|---------|-------------|
| `attempts` | Total number of failed login attempts from an IP |
| `unique_users` | Number of distinct usernames tried |
| `time_window_sec` | Total duration of activity in seconds |
| `avg_interval_sec` | Average time between attempts |
| `success_rate` | Ratio of successful logins to total attempts |

## Example Output (--demo)

```
Generating synthetic training data...

=== Model Evaluation ===
              precision    recall  f1-score   support

      Normal       1.00      1.00      1.00       260
 Brute Force       1.00      1.00      1.00       140

    accuracy                           1.00       400
```

## Example Output (--file)

```
Parsing log file...
Training model on synthetic data...

=== Brute Force Detection Results ===
Total IPs analyzed : 18
Flagged as attack  : 5

Flagged IPs:
  192.168.1.101        attempts=145 users=3 success_rate=0.01
  10.0.0.55            attempts=88  users=2 success_rate=0.00
```
