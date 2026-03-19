import argparse
import re
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win', '.club', '.online'}
BRAND_KEYWORDS = ['paypal', 'apple', 'amazon', 'google', 'microsoft', 'netflix', 'facebook', 'instagram', 'bank', 'secure', 'login', 'account', 'verify', 'update', 'confirm']

def extract_features(url):
    parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
    has_ip = bool(re.match(r'\d+\.\d+\.\d+\.\d+', hostname))
    num_subdomains = len(hostname.split('.')) - 2
    has_at = '@' in url
    has_double_slash = '//' in url[7:]
    url_len = len(url)
    num_digits = sum(c.isdigit() for c in url)
    num_special = sum(c in '-_~' for c in url)
    has_https = url.startswith('https')
    path_depth = path.count('/')
    num_query_params = len(query.split('&')) if query else 0
    brand_in_subdomain = any(b in hostname.split('.')[0].lower() for b in BRAND_KEYWORDS) if num_subdomains > 0 else 0
    brand_in_path = any(b in path.lower() for b in BRAND_KEYWORDS)
    suspicious_tld = tld in SUSPICIOUS_TLDS
    entropy = -sum((url.count(c)/len(url)) * np.log2(url.count(c)/len(url)) for c in set(url) if url.count(c) > 0) if url else 0
    
    return [
        url_len, num_subdomains, int(has_ip), int(has_at), int(has_double_slash),
        num_digits, num_special, int(has_https), path_depth, num_query_params,
        int(brand_in_subdomain), int(brand_in_path), int(suspicious_tld), entropy
    ]

FEATURE_NAMES = [
    'url_length', 'num_subdomains', 'has_ip', 'has_at', 'has_double_slash',
    'num_digits', 'num_special', 'has_https', 'path_depth', 'num_query_params',
    'brand_in_subdomain', 'brand_in_path', 'suspicious_tld', 'entropy'
]

def generate_demo_data(n=500):
    np.random.seed(42)
    legit_urls = [
        'https://www.google.com/search?q=python',
        'https://github.com/user/repo',
        'https://stackoverflow.com/questions/12345',
        'https://amazon.com/dp/B01234',
        'https://en.wikipedia.org/wiki/Machine_learning',
        'https://mail.google.com/mail/u/0/#inbox',
        'https://docs.python.org/3/library/re.html',
    ]
    phishing_urls = [
        'http://paypal-verify.tk/login?user=victim',
        'http://192.168.1.1/apple/id/confirm',
        'http://secure-amazon.xyz/account/update',
        'http://login.microsoft.verify-now.ml/auth',
        'http://netflix.com.account-update.top/billing',
        'http://www.google.com@phishing.com/login',
        'http://amazon-secure.win/login//confirm?id=1234',
    ]
    
    rows = []
    labels = []
    for _ in range(n // 2):
        url = legit_urls[np.random.randint(len(legit_urls))]
        noise = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), np.random.randint(0, 10)))
        rows.append(extract_features(url + noise))
        labels.append(0)
    for _ in range(n // 2):
        url = phishing_urls[np.random.randint(len(phishing_urls))]
        noise = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), np.random.randint(0, 10)))
        rows.append(extract_features(url + noise))
        labels.append(1)
    
    return pd.DataFrame(rows, columns=FEATURE_NAMES), np.array(labels)

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    return clf

def predict_url(clf, url):
    features = np.array(extract_features(url)).reshape(1, -1)
    pred = clf.predict(features)[0]
    prob = clf.predict_proba(features)[0]
    label = 'PHISHING' if pred == 1 else 'LEGITIMATE'
    confidence = prob[pred] * 100
    print(f'{url}')
    print(f'  Result: {label} ({confidence:.1f}% confidence)')
    return pred

def main():
    parser = argparse.ArgumentParser(description='Phishing URL Detector using Random Forest')
    parser.add_argument('--demo', action='store_true', help='Run with synthetic demo data')
    parser.add_argument('--url', type=str, help='URL to classify')
    parser.add_argument('--file', type=str, help='File with URLs to classify (one per line)')
    args = parser.parse_args()

    if args.demo:
        print('Generating synthetic demo data...')
        X, y = generate_demo_data(500)
        print(f'Dataset: {len(X)} samples, {y.sum()} phishing, {(y==0).sum()} legitimate')
        print('\nTraining Random Forest classifier...')
        clf = train_model(X, y)
        
        print('\nSample predictions:')
        test_urls = [
            'https://www.google.com/search?q=cybersecurity',
            'http://paypal-secure.tk/login?confirm=true',
            'https://github.com/user/repo/blob/main/README.md',
            'http://192.168.0.1/amazon/account/verify',
            'https://mail.google.com/mail/u/0/',
        ]
        for url in test_urls:
            predict_url(clf, url)
        return

    if not args.url and not args.file:
        print('Use --demo to run with synthetic data, --url <URL> to classify a URL, or --file <path> for batch.')
        parser.print_help()
        return

    print('Training model with demo data...')
    X, y = generate_demo_data(500)
    clf = train_model(X, y)

    if args.url:
        predict_url(clf, args.url)

    if args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            predict_url(clf, url)

if __name__ == '__main__':
    main()
