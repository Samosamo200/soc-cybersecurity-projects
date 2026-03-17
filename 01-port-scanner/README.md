<div align="center">

# 🔍 Port Scanner

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Kategori](https://img.shields.io/badge/Kategori-SOC%20%2F%20Network-00BCD4?style=for-the-badge)
![Vanskelighet](https://img.shields.io/badge/Niv%C3%A5-Nybegynner-00C853?style=for-the-badge)

> **Finn hvilke porter som er åpne på en nettverksvert.**  
> Brukes i SOC for å kartlegge hva som er eksponert mot internett.

</div>

---

## 📖 Hva er en port scanner?

Når en datamaskin kommuniserer over nett, bruker den **porter** — tenk på dem som dører inn til ulike tjenester. Port `80` er HTTP (nettsider), `22` er SSH (fjerninnlogging), `443` er HTTPS, og så videre.

En **port scanner** banker på alle dørene og registrerer hvilke som er åpne. I SOC brukes dette til å:

- 🗺️ **Kartlegge angrepsflaten** — hvilke tjenester er synlige utenfra?
- ⚠️ **Finne eksponerte tjenester** — er det noe som ikke burde vært åpent?
- 📋 **Lage inventar** — dokumentere alle aktive tjenester i nettverket

---

## ⚙️ Slik fungerer det

```
Bruker → scanner.py → sender TCP SYN til hver port
                    ↓
         Port svarer?  →  JA  → Port er ÅPEN  ✅
                        NEI  → Port er LUKKET ❌
```

Scriptet bruker **multithreading** — det sjekker mange porter samtidig i stedet for én om gangen. Det gjør skanningen mye raskere.

---

## 🚀 Bruk

```bash
# Skann standard porter (1-1024)
python3 scanner.py 192.168.1.1

# Skann et bestemt portintervall
python3 scanner.py 192.168.1.1 --ports 1-65535

# Skann din egen maskin
python3 scanner.py 127.0.0.1 --ports 1-1000
```

---

## 📊 Eksempel på output

```
Skanner 192.168.1.1 (1-1024)...
  22/tcp   open     ← SSH (fjerninnlogging)
  80/tcp   open     ← HTTP (nettside)
  443/tcp  open     ← HTTPS (sikker nettside)
```

---

## 🧩 Konsepter brukt

| Konsept | Forklaring |
|---------|------------|
| `socket` | Pythons innebygde nettverksbibliotek |
| `TCP connect scan` | Fullfører TCP-håndtrykket for å sjekke porten |
| `ThreadPoolExecutor` | Kjører mange skanninger parallelt |
| `connect_ex()` | Returnerer `0` hvis porten er åpen |

---

## ⚠️ Viktig

> **Skann kun nettverk og systemer du har tillatelse til å teste.**  
> Uautorisert portskanning kan være ulovlig.

---

<div align="center">

[← Tilbake til repo](../README.md)

</div>
