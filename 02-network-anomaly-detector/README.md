<div align="center">

# 🤖 Network Anomaly Detector

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![ML](https://img.shields.io/badge/scikit--learn-Isolation%20Forest-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Kategori](https://img.shields.io/badge/Kategori-Machine%20Learning-9C27B0?style=for-the-badge)
![Vanskelighet](https://img.shields.io/badge/Niv%C3%A5-Middels-FF9800?style=for-the-badge)

> **Oppdager unormal nettverkstrafikk automatisk — uten å kjenne angrepet på forhånd.**  
> Brukes i SOC for å finne nye og ukjente trusler i nettverket.

</div>

---

## 📖 Hva er anomali-deteksjon?

Tradisjonelle sikkerhetsverktøy som brannmurer bruker **signaturer** — en liste over kjente angrep. Problemet er at nye angrep ikke har noen signatur ennå.

**Anomali-deteksjon** løser dette ved å lære hva som er *normalt*, og så flagge alt som avviker fra normalen — selv om angrepet aldri er sett før.

```
Normal trafikk:    100KB/s  →  ikke flagget ✅
Normal trafikk:    150KB/s  →  ikke flagget ✅
Anomali (angrep):  50MB/s   →  FLAGGET 🚨
```

---

## 🌲 Isolation Forest — algoritmen

**Isolation Forest** er en unsupervised ML-algoritme. Det betyr at den trenes uten eksempler på angrep — den trenger kun normal trafikk.

Slik fungerer den:

```
1. Bygg et tilfeldig beslutningstre
2. Del dataen ved å velge en tilfeldig feature og en tilfeldig terskel
3. Tell hvor mange splitter som trengs for å isolere et datapunkt
4. Anomalier isoleres raskt (få splitter) → de er "rare"
5. Normale punkter trenger mange splitter → de ligner på hverandre
```

<div align="center">

```
          [Normalt]              [Anomali]
         /    |    \               |
        /     |     \             split
       /      |      \          isolert! 🚨
     split   split   split
    (mange splitter = normalt)
```

</div>

---

## 📊 Features (variabler modellen ser på)

| Feature | Forklaring | Typisk normalverdi |
|---------|------------|-------------------|
| `bytes_sent` | Bytes sendt per sesjon | ~5 000 |
| `bytes_recv` | Bytes mottatt per sesjon | ~10 000 |
| `duration` | Sesjonslengde i sekunder | ~30 sek |
| `port` | Destinasjonsport | 80, 443, 22, 53 |
| `packets` | Antall pakker i sesjonen | ~50 |

---

## 🚀 Bruk

```bash
# Installer avhengigheter
pip install scikit-learn pandas numpy

# Kjør med demo-data (syntetiske data genereres automatisk)
python3 anomaly_detector.py --demo

# Kjør med din egen CSV-fil
python3 anomaly_detector.py --csv trafikk.csv
```

---

## 📁 CSV-format

Hvis du bruker din egen fil, trenger den disse kolonnene:

```csv
bytes_sent,bytes_recv,duration,port,packets
5200,9800,28,443,47
4900,10200,31,80,52
500000,150,0.8,4444,4900   ← dette vil bli flagget som anomali
```

---

## 📊 Eksempel på output

```
Totalt: 520 rader | Anomalier: 22

  bytes_sent  bytes_recv  duration  port  packets  anomaly
  498234.0      182.3       0.7    4444   4923.0     -1
  502891.0      201.1       0.9    1337   5102.0     -1
```

> `anomaly = -1` betyr at Isolation Forest har flagget raden som unormal.

---

## 🧩 Konsepter brukt

| Konsept | Forklaring |
|---------|------------|
| `IsolationForest` | Unsupervised anomali-deteksjon |
| `StandardScaler` | Normaliserer features til samme skala |
| `contamination=0.05` | Forventer at ~5% av dataen er anomalier |
| `fit_predict()` | Trener modellen og klassifiserer samtidig |

---

## 🔗 Videre lesning

- [Isolation Forest — scikit-learn docs](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [Anomaly Detection in Network Traffic](https://www.sans.org/reading-room/)

---

<div align="center">

[← Tilbake til repo](../README.md)

</div>
