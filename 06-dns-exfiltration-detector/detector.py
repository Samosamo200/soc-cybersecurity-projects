import argparse
import math
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())


def extract_subdomain(domain):
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


def extract_features(domains):
    records = []
    for d in domains:
        sub = extract_subdomain(d)
        query_len = len(d)
        sub_len = len(sub)
        entropy = shannon_entropy(sub) if sub else shannon_entropy(d)
        unique_ratio = len(set(d)) / query_len if query_len else 0
        digit_ratio = sum(c.isdigit() for c in d) / query_len if query_len else 0
        records.append({
            "domain": d,
            "query_len": query_len,
            "sub_len": sub_len,
            "entropy": entropy,
            "unique_ratio": unique_ratio,
            "digit_ratio": digit_ratio,
        })
    return pd.DataFrame(records)


def generate_demo_data(n_normal=9500, n_exfil=500):
    rng = np.random.default_rng(42)

    tlds = ["com", "net", "org", "io"]
    normal_domains = []
    words = ["mail", "cdn", "api", "static", "assets", "update", "auth", "login",
             "www", "ftp", "smtp", "pop", "imap", "vpn", "proxy", "ntp", "dns"]
    for _ in range(n_normal):
        sub = rng.choice(words)
        domain = f"{sub}.example.{rng.choice(tlds)}"
        normal_domains.append(domain)

    exfil_domains = []
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+/"
    for _ in range(n_exfil):
        length = int(rng.integers(20, 55))
        payload = "".join(rng.choice(list(alphabet)) for _ in range(length))
        exfil_domains.append(f"{payload}.evil.{rng.choice(tlds)}")

    return normal_domains + exfil_domains


def run_demo(contamination):
    print("[*] Generating synthetic DNS queries...")
    domains = generate_demo_data()
    df = extract_features(domains)
    feature_cols = ["query_len", "sub_len", "entropy", "unique_ratio", "digit_ratio"]
    X = df[feature_cols].values
    model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    print("[*] Training Isolation Forest  (contamination={})".format(contamination))
    model.fit(X)
    df["prediction"] = model.predict(X)
    df["prediction"] = df["prediction"].map({1: "normal", -1: "ANOMALY"})
    anomalies = df[df["prediction"] == "ANOMALY"]
    print(f"
=== Flagged as potential DNS exfiltration ===")
    print(anomalies[["domain", "entropy", "query_len", "prediction"]].head(10).to_string(index=False))
    print(f"
[+] {len(anomalies)} anomalous queries detected out of {len(df)}")
    return df


def run_file(path, domain_col, contamination, output):
    try:
        df_raw = pd.read_csv(path, sep=None, engine="python")
    except Exception as e:
        print(f"[!] Could not read file: {e}")
        sys.exit(1)
    if domain_col not in df_raw.columns:
        print(f"[!] Column '{domain_col}' not found. Available: {list(df_raw.columns)}")
        sys.exit(1)
    domains = df_raw[domain_col].astype(str).tolist()
    print(f"[*] Loaded {len(domains)} queries")
    df = extract_features(domains)
    for col in df_raw.columns:
        if col != domain_col:
            df[col] = df_raw[col].values
    feature_cols = ["query_len", "sub_len", "entropy", "unique_ratio", "digit_ratio"]
    X = df[feature_cols].values
    model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    print(f"[*] Training Isolation Forest  (contamination={contamination})")
    model.fit(X)
    df["prediction"] = model.predict(X)
    df["prediction"] = df["prediction"].map({1: "normal", -1: "ANOMALY"})
    anomalies = df[df["prediction"] == "ANOMALY"]
    print(f"
=== Flagged as potential DNS exfiltration ===")
    print(anomalies[["domain", "entropy", "query_len", "prediction"]].head(20).to_string(index=False))
    print(f"
[+] {len(anomalies)} anomalous queries detected out of {len(df)}")
    if output:
        anomalies.to_csv(output, index=False)
        print(f"[+] Saved flagged rows to {output}")
    return df


def main():
    parser = argparse.ArgumentParser(description="DNS Exfiltration Detector")
    parser.add_argument("--file", help="Path to DNS log CSV")
    parser.add_argument("--domain-col", default="domain", help="Column name for domain strings")
    parser.add_argument("--contamination", type=float, default=0.05, help="Expected anomaly fraction")
    parser.add_argument("--demo", action="store_true", help="Run with synthetic demo data")
    parser.add_argument("--output", help="Save flagged rows to this CSV path")
    args = parser.parse_args()

    if args.demo:
        run_demo(args.contamination)
    elif args.file:
        run_file(args.file, args.domain_col, args.contamination, args.output)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
