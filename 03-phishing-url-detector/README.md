# 03 – Phishing URL Detector

A machine learning tool that classifies URLs as **phishing** or **legitimate** using a Random Forest classifier trained on URL-based features.

## Features extracted

- URL length and entropy
- Number of subdomains
- IP address in hostname
- Presence of `@` or double slashes
- HTTPS usage
- Path depth and query parameters
- Brand keywords in subdomain or path
- Suspicious TLDs (`.tk`, `.ml`, `.xyz`, etc.)

## Requirements

```
pip install scikit-learn pandas numpy
```

## Usage

```bash
# Run demo with synthetic data
python detector.py --demo

# Classify a single URL
python detector.py --url "http://paypal-secure.tk/login"

# Classify URLs from a file
python detector.py --file urls.txt
```

## Demo output

```
Generating synthetic demo data...
Dataset: 500 samples, 250 phishing, 250 legitimate

Training Random Forest classifier...
              precision    recall  f1-score   support
   Legitimate       0.95      0.96      0.95        52
     Phishing       0.96      0.94      0.95        48
    
http://paypal-secure.tk/login?confirm=true
  Result: PHISHING (97.0% confidence)
https://www.google.com/search?q=cybersecurity
  Result: LEGITIMATE (98.0% confidence)
```

## Notes

- The `--demo` flag uses synthetically generated URLs for testing without real data
- For production use, train on a labeled dataset such as [PhishTank](https://phishtank.org/) or [OpenPhish](https://openphish.com/)
- Model is retrained on each run; add `joblib` persistence for production deployments
