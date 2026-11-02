# UNSW-NB15 Benchmark Dataset Subset

## Overview
This folder contains a curated, balanced benchmark subset of the **UNSW-NB15** Network Intrusion Detection dataset, created by the Cyber Range Lab of the Australian Centre for Cyber Security (ACCS).

* **File:** `UNSW_NB15_sample.csv`
* **Size:** ~1.87 MB
* **Total Records:** 10,000 samples
* **Features:** 45 network traffic features (packet rates, bytes, duration, TTL, TCP window sizes, service flags, jitter, entropy indicators)

---

## Class Distribution

| Class | Count | Percentage | Description |
| :--- | :---: | :---: | :--- |
| **Normal (0)** | 5,000 | 50.0% | Benign background network activities |
| **Attack (1)** | 5,000 | 50.0% | Real-world simulated cyber attack vectors |

### Breakdown of Attack Categories:
- **Exploits:** 2,111
- **DoS (Denial of Service):** 1,289
- **Fuzzers:** 783
- **Reconnaissance (Port Scans / Probes):** 623
- **Analysis:** 97
- **Shellcode:** 61
- **Backdoor:** 29
- **Worms:** 7

---

## Role in Mini-Project (U23CS704)
1. **Literature Survey Benchmark (Slides 5 & 10):**
   Used as the primary reference standard to evaluate flow features, packet rate distributions, and port dispersion patterns.
2. **Offline Validation:**
   Serves as ground-truth verification data to cross-validate our live detection engines (**LightGBM Threat Classifier** & **PyTorch Deep Autoencoder**).
3. **Live Demonstration Contrast:**
   - **Offline Mode:** Tested against `UNSW_NB15_sample.csv`.
   - **Online Mode:** Captured live off network interface using **Scapy** and verified against active multi-vector attack generator (`packet_simulator.py`).
