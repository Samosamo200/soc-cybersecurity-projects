import argparse
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def extract_features(df):
    df['query_length'] = df['query'].str.len()
    df['subdomain_count'] = df['query'].str.count(r'\.')
    df['entropy'] = df['query'].apply(compute_entropy)
    df['digit_ratio'] = df['query'].apply(lambda q: sum(c.isdigit() for c in q) / max(len(q), 1))
    df['unique_char_ratio'] = df['query'].apply(lambda q: len(set(q)) / max(len(q), 1))
    return df[['query_length', 'subdomain_count', 'entropy', 'digit_ratio', 'unique_char_ratio']]

def compute_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * np.log2(p) for p in probs if p > 0)

def generate_demo_data():
    np.random.seed(42)
    normal_queries = [
        f"{''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz'), size=np.random.randint(4, 10)))}.example.com"
        for _ in range(200)
    ]
    malicious_queries = [
        f"{''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), size=np.random.randint(30, 60)))}.evil.io"
        for _ in range(20)
    ]
    queries = normal_queries + malicious_queries
    labels = ['normal'] * 200 + ['exfiltration'] * 20
    df = pd.DataFrame({'query': queries, 'label': labels})
    return df

def train_model(features):
    scaler = StandardScaler()
    X = scaler.fit_transform(features)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    return model, scaler

def detect(model, scaler, features):
    X = scaler.transform(features)
    scores = model.decision_function(X)
    predictions = model.predict(X)
    return predictions, scores

def main():
    parser = argparse.ArgumentParser(description='DNS Exfiltration Detector')
    parser.add_argument('--demo', action='store_true', help='Run with synthetic demo data')
    parser.add_argument('--input', type=str, help='CSV file with a "query" column')
    parser.add_argument('--threshold', type=float, default=-0.1, help='Anomaly score threshold')
    args = parser.parse_args()

    if args.demo:
        df = generate_demo_data()
        print(f"[Demo] Loaded {len(df)} DNS queries ({df['label'].value_counts().to_dict()})")
    elif args.input:
        df = pd.read_csv(args.input)
        if 'query' not in df.columns:
            print("Error: CSV must contain a 'query' column")
            return
        print(f"Loaded {len(df)} DNS queries from {args.input}")
    else:
        parser.print_help()
        return

    features = extract_features(df)
    model, scaler = train_model(features)
    predictions, scores = detect(model, scaler, features)

    df['anomaly_score'] = scores
    df['prediction'] = np.where(predictions == -1, 'EXFILTRATION', 'normal')

    flagged = df[df['prediction'] == 'EXFILTRATION']
    print(f"\nDetected {len(flagged)} suspicious DNS queries out of {len(df)} total")

    if len(flagged) > 0:
        print("\nTop flagged queries:")
        print(flagged[['query', 'anomaly_score']].sort_values('anomaly_score').head(10).to_string(index=False))

    if args.demo and 'label' in df.columns:
        tp = len(df[(df['prediction'] == 'EXFILTRATION') & (df['label'] == 'exfiltration')])
        fp = len(df[(df['prediction'] == 'EXFILTRATION') & (df['label'] == 'normal')])
        fn = len(df[(df['prediction'] == 'normal') & (df['label'] == 'exfiltration')])
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        print(f"\n[Demo Stats] TP={tp}, FP={fp}, FN={fn}")
        print(f"Precision: {precision:.2f}  Recall: {recall:.2f}")

if __name__ == '__main__':
    main()
