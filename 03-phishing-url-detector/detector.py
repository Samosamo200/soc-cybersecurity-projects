import argparse
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import re

def extract_features(url):
    features = []
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('='))
    features.append(url.count('&'))
    features.append(1 if 'https' in url else 0)
    features.append(url.count('/'))
    features.append(len(re.findall(r'\d', url)))
    features.append(1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0)
    features.append(len(url.split('/')[2]) if len(url.split('/')) > 2 else 0)
    features.append(url.count('%'))
    features.append(1 if any(w in url.lower() for w in ['login', 'secure', 'account', 'verify', 'bank', 'update']) else 0)
    return features

def generate_demo_data():
    legit_urls = [
        'https://www.google.com/search?q=python',
        'https://github.com/user/repo',
        'https://stackoverflow.com/questions/123456',
        'https://docs.python.org/3/library/',
        'https://www.wikipedia.org/wiki/Machine_learning',
        'https://www.amazon.com/products',
        'https://www.reddit.com/r/python',
        'https://news.ycombinator.com',
        'https://www.youtube.com/watch?v=abc123',
        'https://www.linkedin.com/in/user',
    ]
    phishing_urls = [
        'http://192.168.1.1/login/verify?user=admin&token=abc',
        'http://secure-bank-login.xyz/account/update',
        'http://paypa1.com/verify-account?id=123&secure=true',
        'http://amazon-security.tk/login?redirect=true',
        'http://google-verify.ml/account?user=test@test.com',
        'http://facebook-secure.info/login/verify',
        'http://apple-id-verify.tk/account-update',
        'http://microsofft.com/outlook/login?email=user',
        'http://dropbox-secure.xyz/verify?token=abc123',
        'http://netflix-account.tk/verify/payment',
    ]
    urls = legit_urls + phishing_urls
    labels = [0] * len(legit_urls) + [1] * len(phishing_urls)
    for _ in range(200):
        legit = f'https://www.example{np.random.randint(1,100)}.com/page{np.random.randint(1,50)}'
        urls.append(legit)
        labels.append(0)
    for _ in range(200):
        phish = f'http://secure-verify-{np.random.randint(1,100)}.xyz/login?user=victim&token={"x"*np.random.randint(5,20)}'
        urls.append(phish)
        labels.append(1)
    return urls, labels

def train_and_evaluate(urls, labels):
    X = [extract_features(u) for u in urls]
    X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    return clf

def predict_url(clf, url):
    features = [extract_features(url)]
    pred = clf.predict(features)[0]
    prob = clf.predict_proba(features)[0]
    label = 'PHISHING' if pred == 1 else 'LEGITIMATE'
    confidence = prob[pred] * 100
    print(f'URL: {url}')
    print(f'Prediction: {label} ({confidence:.1f}% confidence)')

def main():
    parser = argparse.ArgumentParser(description='Phishing URL Detector')
    parser.add_argument('--demo', action='store_true', help='Run with synthetic demo data')
    parser.add_argument('--url', type=str, help='URL to classify')
    args = parser.parse_args()

    if args.demo:
        print('=== Phishing URL Detector - Demo Mode ===')
        urls, labels = generate_demo_data()
        print(f'Training on {len(urls)} URLs...')
        clf = train_and_evaluate(urls, labels)
        test_urls = [
            'https://www.google.com/search?q=phishing',
            'http://secure-bank-login.xyz/account/verify?user=victim',
        ]
        print('\nPredictions on sample URLs:')
        for url in test_urls:
            predict_url(clf, url)
            print()
    elif args.url:
        urls, labels = generate_demo_data()
        clf = train_and_evaluate(urls, labels)
        predict_url(clf, args.url)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
