# 03 - Phishing URL Detector

A machine learning classifier that detects phishing URLs using a Random Forest model trained on URL-based features.

## Features

- Extracts 14 features from URLs (length, special characters, IP presence, suspicious keywords, etc.)
- Trained with a Random Forest classifier (100 estimators)
- Supports demo mode with synthetic training data
- Can classify any URL from the command line

## Requirements

```
scikit-learn
numpy
```

Install with:
```bash
pip install scikit-learn numpy
```

## Usage

### Demo mode (synthetic data)
```bash
python detector.py --demo
```

### Classify a specific URL
```bash
python detector.py --url "http://secure-bank-login.xyz/verify?user=victim"
```

## How It Works

1. Extracts features from the URL: length, number of dots, dashes, special chars, presence of IP address, HTTPS usage, suspicious keywords, etc.
2. Feeds features into a Random Forest classifier
3. Returns a prediction (LEGITIMATE or PHISHING) with confidence score

## Example Output

```
=== Phishing URL Detector - Demo Mode ===
Training on 420 URLs...
              precision    recall  f1-score   support

  Legitimate       0.98      0.97      0.97        60
    Phishing       0.96      0.97      0.97        24

    accuracy                           0.97        84

Predictions on sample URLs:
URL: https://www.google.com/search?q=phishing
Prediction: LEGITIMATE (97.0% confidence)

URL: http://secure-bank-login.xyz/account/verify?user=victim
Prediction: PHISHING (95.0% confidence)
```
