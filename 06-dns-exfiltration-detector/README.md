# 06 - DNS Exfiltration Detector

Detects DNS-based data exfiltration using anomaly detection with Isolation Forest. Analyses DNS query features such as entropy, length, and character composition to flag suspicious queries that may indicate covert data tunnelling.

## How It Works

DNS exfiltration encodes data into DNS query subdomains to bypass firewalls. This tool extracts statistical features from DNS queries and uses an unsupervised Isolation Forest model to identify anomalous patterns typical of exfiltration.

**Features extracted:**
- Query length
- Subdomain depth (dot count)
- Shannon entropy of the query string
- Digit-to-character ratio
- Unique character ratio

## Requirements

```
pip install scikit-learn pandas numpy
```

## Usage

```bash
# Run with synthetic demo data
python detector.py --demo

# Run on your own CSV (must have a "query" column)
python detector.py --input dns_logs.csv
```

## Demo Output Example

```
[Demo] Loaded 220 DNS queries ({'normal': 200, 'exfiltration': 20})

Detected 11 suspicious DNS queries out of 220 total

Top flagged queries:
                                               query  anomaly_score
  a3b9f2e1c8d7g4h5j6k0m1n2p3q4r5s6t7u8v9w0x1y2z3.evil.io        -0.21
  ...

[Demo Stats] TP=10, FP=1, FN=10
Precision: 0.91  Recall: 0.50
```

## Input Format

CSV file with at minimum a `query` column containing fully qualified domain names:

```csv
query
www.google.com
update.microsoft.com
aGVsbG8gd29ybGQ.malicious.xyz
```

## Limitations

- Unsupervised model — no labelled training data required, but tuning `contamination` may be needed
- High-entropy legitimate domains (CDNs, hashed URLs) may cause false positives
- Does not inspect DNS response payloads, only query strings
