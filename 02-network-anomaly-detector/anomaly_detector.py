import argparse
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def generate_demo_data():
    np.random.seed(42)
    normal = pd.DataFrame({
        'bytes_sent': np.random.normal(5000, 1000, 500),
        'bytes_recv': np.random.normal(10000, 2000, 500),
        'duration': np.random.normal(30, 10, 500),
        'port': np.random.choice([80, 443, 22, 53], 500),
        'packets': np.random.normal(50, 15, 500)
    })
    anomalies = pd.DataFrame({
        'bytes_sent': np.random.normal(500000, 50000, 20),
        'bytes_recv': np.random.normal(200, 50, 20),
        'duration': np.random.normal(1, 0.5, 20),
        'port': np.random.choice([4444, 1337, 31337], 20),
        'packets': np.random.normal(5000, 500, 20)
    })
    return pd.concat([normal, anomalies], ignore_index=True)

def detect(df):
    features = ['bytes_sent', 'bytes_recv', 'duration', 'port', 'packets']
    X = df[features].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(contamination=0.05, random_state=42)
    df['anomaly'] = model.fit_predict(X_scaled)
    return df[df['anomaly'] == -1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', help='CSV fil med nettverkstrafikk')
    parser.add_argument('--demo', action='store_true')
    args = parser.parse_args()

    if args.demo:
        df = generate_demo_data()
    elif args.csv:
        df = pd.read_csv(args.csv)
    else:
        print('Bruk --demo eller --csv <fil>')
        return

    anomalies = detect(df)
    print(f'Totalt: {len(df)} rader | Anomalier: {len(anomalies)}')
    print(anomalies.to_string(index=False))

if __name__ == '__main__':
    main()
