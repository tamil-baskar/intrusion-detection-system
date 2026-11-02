# Real-Time Network Intrusion Detection System (IDS) V5

> **U23CS704 Mini Project — Sona College of Technology**
> 
> A live, terminal-based IDS that captures network packets with Scapy, classifies threats using a hybrid rule-based + ML ensemble (LightGBM + PyTorch Autoencoder), and renders a self-refreshing Rich dashboard.

---

## Features

- **Live Packet Capture** — Scapy sniffs on the best available interface automatically
- **Deep Packet Inspection (DPI)** — TLS SNI extraction identifies domains from encrypted HTTPS traffic
- **7 Heuristic Rules** — SYN Flood, LAND Attack, XMAS Scan, NULL Scan, Port Scan, Volumetric DoS, Automated Bot
- **ML Ensemble Detection** — LightGBM classifier + PyTorch Autoencoder for novel anomaly detection
- **GeoIP / ASN Lookup** — Resolves IPs to organisation names via MaxMind GeoLite2-ASN
- **Rich Terminal Dashboard** — Live ASCII traffic graph, Top Active IPs, scrollable sessions table, per-IP threat drill-down
- **Persistent Alert Logging** — Every detection written to `alerts.log` with timestamp and context
- **9-Mode Attack Simulator** — `packet_simulator.py` covers all common attack vectors for demo/testing
- **Automated Test Suite** — `auto_tester.py` runs all attack scripts and reports PASS/FAIL

---

## Project Structure

```
intrusion-detection-system-main/
│
├── detector.py              # Main IDS — sniffer + heuristics + ML + dashboard
├── packet_simulator.py      # Attack simulator (9 modes: DoS, SYN, XMAS, NULL, etc.)
├── normal.py                # Benign traffic simulator (Google HTTPS, zero-flag)
├── auto_tester.py           # Automated test suite (PASS/FAIL report)
├── attack.py                # Volumetric DoS (UDP flood)
├── advanced_attack.py       # LAND Attack + XMAS Scan + NULL Scan
├── scanner.py               # Port Scan + Automated Bot
├── syn_flood.py             # TCP SYN Flood
├── demo_detector.py         # Condensed version for report (~270 lines)
│
├── training_model/
│   ├── ml_engine_v2.py      # LightGBM + PyTorch Autoencoder + Ensemble Manager
│   ├── train_lightgbm.py    # Train the LightGBM classifier
│   ├── train_autoencoder.py # Train the PyTorch Autoencoder
│   └── models/
│       ├── lgbm_threat.joblib   # Saved LightGBM model
│       ├── autoencoder.pth      # Saved Autoencoder weights
│       └── ae_meta.joblib       # Saved scaler + MSE threshold
│
├── diagrams/                # System Architecture, Class, Use Case, Activity diagrams
├── datasets/
│   └── README.md            # UNSW-NB15 dataset description
│
├── requirements.txt
└── .gitignore
```

---

## Prerequisites

- **Python 3.9+**
- **Npcap** (Windows) — required for Scapy packet capture  
  Download: https://npcap.com/#download  
- **MaxMind GeoLite2-ASN database** (`GeoLite2-ASN.mmdb`) — place in project root  
  Download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/intrusion-detection-system.git
cd intrusion-detection-system

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Place GeoLite2-ASN.mmdb in the project root

# 5. (Optional) Re-train ML models
cd training_model
python train_lightgbm.py
python train_autoencoder.py
cd ..
```

---

## Usage

### Step 1 — Start the IDS Dashboard (run as Administrator / sudo)
```bash
python detector.py
```

### Step 2 — In a second terminal, run a simulation
```bash
python packet_simulator.py   # then press 10 → Enter for ALL attacks
python normal.py             # benign traffic (shows NORMAL / green)
python auto_tester.py        # automated PASS/FAIL test suite
```

### Stop everything
```powershell
Stop-Process -Name python -Force   # Windows
```

### Dashboard Controls
| Key | Action |
|-----|--------|
| `↑` / `↓` | Select an IP row |
| `Enter` | Open Threat Details panel |
| `ESC` | Return to dashboard |
| `Q` | Quit |

---

## ML Architecture

| Model | Type | Input | Detection Method |
|-------|------|-------|-----------------|
| **LightGBM** | Supervised (GBDT) | 6 features | `attack_prob >= 0.50` |
| **PyTorch Autoencoder** | Unsupervised | 6 features | `MSE > 99th-percentile threshold` |
| **Ensemble** | OR vote | Both | Either model flags → alert |

**6 Features:** `rate`, `ports_count`, `syn_count`, `payload_entropy`, `syn_ratio`, `port_diversity`

---

## Attack Detection Summary

| Attack | Method | Trigger |
|--------|--------|---------|
| Volumetric DoS | Heuristic | rate > 350 pkt/s |
| SYN Flood | Heuristic | syn_count > 50 per IP |
| Port Scan | Heuristic | unique_ports >= 10 |
| LAND Attack | Heuristic | src_ip == dst_ip |
| XMAS Scan | Heuristic | TCP flags FIN+PSH+URG |
| NULL Scan | Heuristic | TCP flags == 0x00 |
| Automated Bot | Heuristic | rate > 80 + uniform payload |
| ML Anomaly | LightGBM + AE | Ensemble vote |

---

## Dataset

**UNSW-NB15** — 10,000 balanced records (50% Normal / 50% Attack) used for benchmark cross-validation.  
See `datasets/README.md` for details. CSV files are excluded from this repo due to size.

---

## SDG Alignment

This project supports:
- **SDG 9** — Industry, Innovation and Infrastructure (resilient digital infrastructure)
- **SDG 16** — Peace, Justice and Strong Institutions (cybersecurity governance)

---

## Academic Context

> Course: U23CS704 | Institution: Sona College of Technology

---

## License

This project is for academic and educational purposes only.  
All attack simulations use spoofed RFC-1918 private IPs directed to loopback (127.0.0.1) — no real network harm.
