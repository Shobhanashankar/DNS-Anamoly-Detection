# 🛡️ Real-time DNS Anomaly Detection using Machine Learning

## 📖 Overview
This project detects **anomalous DNS queries** that may indicate malicious activity such as DGA-based attacks, tunneling, or data exfiltration. It uses real-time packet sniffing and **machine learning (Isolation Forest)** for anomaly detection based on domain name characteristics.

---

## 🚀 Features
- ✅ Real-time DNS packet sniffing (via `Scapy`)
- ✅ Domain feature extraction (entropy, length, etc.)
- ✅ Unsupervised anomaly detection using Isolation Forest
- ✅ Visualizations for anomaly distribution and feature behavior
- ✅ Supports plaintext domain lists (like OpenDNS top domains)

---

## 🛠️ Installation
Install all required packages:

```bash
pip install scapy pandas numpy joblib matplotlib seaborn scikit-learn


> **Windows Users**: Install [Npcap](https://nmap.org/npcap/) to allow Scapy to sniff packets on Windows.

---

## 📁 Dataset

The domain dataset used for this project is sourced from the official [OpenDNS Public Domain Lists](https://github.com/opendns/public-domain-lists/blob/master/opendns-top-domains.txt).  
This list includes the most commonly queried domains across OpenDNS's global network and is used to simulate **benign DNS traffic**.

Save the file as `opendns-top-domains.txt`, where each line should contain one domain:



```
google.com
facebook.com
youtube.com
...
```

The script will automatically convert this into a CSV file (`dns_dataset.csv`) for feature extraction.

---

## 🧠 Features Used for Detection
- `domain_length`: Number of characters in the domain name
- `num_subdomains`: Number of dots in the domain
- `entropy`: Randomness of the domain name characters
- `special_chars`: Number of special characters (!, @, #, $, etc.)

---

## 🤖 ML Model
- **Model:** Isolation Forest
- **Type:** Unsupervised anomaly detection
- **Labels:**
  - `1` → Normal
  - `-1` → Anomalous

---

## 📊 Visualizations
The script automatically generates:
- 📈 **Scatter Plot**: Domain Length vs. Entropy (Anomalies in red)
- 📊 **Bar Chart**: Count of Normal vs. Anomalous queries

Saved as:  
```bash
anomaly_visualization.png
```

---

## 🚦 How to Run

```bash
python DNS_anomaly.py
```

This will:
1. Convert your `.txt` domain list to CSV
2. Extract features
3. Train the ML model
4. Detect anomalies
5. Save visualizations

---

## 💡 Insights
- Domains with high entropy and longer lengths are often DGA-generated and potentially malicious.
- Legitimate domains are short, clean, and use fewer subdomains or symbols.
- The model detects novel, never-seen-before threats — useful against zero-day DNS abuse.

---
