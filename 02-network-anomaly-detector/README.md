# Network Anomaly Detector

Oppdager nettverksanomalier med Isolation Forest (unsupervised ML).

## Avhengigheter
```
pip install scikit-learn pandas numpy
```

## Bruk
```
python3 anomaly_detector.py --csv traffic.csv
python3 anomaly_detector.py --demo
```

## Features
- bytes_sent, bytes_recv, duration, port, packets
