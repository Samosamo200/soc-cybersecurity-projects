# DNS Exfiltration Detector

An anomaly-based machine learning detector that identifies DNS exfiltration attempts by analysing per-query features such as subdomain entropy, query length, and request frequency.

## How it works

DNS exfiltration encodes data in DNS queries (e.g. `aGVsbG8...base64...evil.com`).  
Key signals exploited by the model:

| Feature | Why it matters |
|---------|----------------|
| Subdomain entropy | Encoded payloads have high Shannon entropy |
| Query length | Exfil queries are typically much longer than normal |
| Subdomain length | Same reasoning as total length |
| Unique char ratio | High ratio → random/encoded content |
| Digit ratio | Base64/hex payloads contain more digits |

An **Isolation Forest** (unsupervised) marks queries that deviate strongly from the normal baseline as anomalies.

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

## Usage

### Demo mode (synthetic data, no real DNS log needed)

```bash
python detector.py --demo
```

### Analyse a real DNS log

The log file should be a CSV (or whitespace-separated) with at minimum a column containing the queried domain name.

```bash
python detector.py --file dns.log --domain-col qname
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--file` | — | Path to DNS log file |
| `--domain-col` | `domain` | Column name that holds the domain string |
| `--contamination` | `0.05` | Expected fraction of anomalies (0–0.5) |
| `--demo` | — | Run with synthetic data |
| `--output` | — | Save flagged rows to this CSV path |

## Example output

```
[*] Loaded 10000 queries
[*] Extracted features
[*] Training Isolation Forest  (contamination=0.05)
[*] Detection complete

=== Flagged as potential DNS exfiltration ===
                                  domain  entropy  query_len  ...  prediction
2847  aGVsbG8td29ybGQ.exfil.example.com     4.81        34   ...  ANOMALY
...
[+] 500 anomalous queries detected out of 10000
```

## Project structure

```
06-dns-exfiltration-detector/
├── detector.py
└── README.md
```

## Notes

- Tuned for demo purposes; retrain on your own baseline traffic for production use.
- Works entirely offline – no external API calls.
