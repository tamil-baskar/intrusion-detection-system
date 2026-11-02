"""
normal.py — Benign Network Traffic Simulator (Zero-Flag / Clean Session)
========================================================================
Simulates realistic, legitimate user web browsing to trusted domains (e.g. Google).
Transfers realistic packets with diverse payload sizes, standard HTTPS (port 443),
and TLS SNI headers so it appears as a recognized clean domain on the IDS dashboard
with NO ALERTS (Alert Status: Normal / Final Verdict: NORMAL).

Usage:
    python normal.py
"""

import warnings
warnings.filterwarnings("ignore", module="cryptography")

import platform
import subprocess
import random
import time
import json
import os
from pathlib import Path
from scapy.all import sendp, IP, TCP, Raw, Ether, conf, getmacbyip, IFACES
from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, ServerName

# ─── Status file for detector.py dashboard integration ─────────────────────────
SIM_STATUS_FILE = Path(__file__).parent / ".sim_status.json"

def _update_status(mode: str, packets_sent: int):
    try:
        data = {
            "mode": mode,
            "packets_sent": packets_sent,
            "updated_at": time.time()
        }
        tmp = str(SIM_STATUS_FILE) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, str(SIM_STATUS_FILE))
    except Exception:
        pass

def _clear_status():
    _update_status("INACTIVE", 0)

# ─── Interface & Gateway Resolution ───────────────────────────────────────────
def get_best_iface():
    try:
        iface_name, _, _ = conf.route.route("8.8.8.8")
        return iface_name
    except Exception:
        for guid, iface in IFACES.items():
            ip = getattr(iface, "ip", "") or ""
            if ip and ip != "127.0.0.1" and not ip.startswith("169.254."):
                return guid
        return conf.iface

def get_gateway_mac(ip: str):
    if platform.system() == "Windows":
        return getmacbyip(ip)
    subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                    return parts[3]
    except Exception:
        pass
    return None

def main():
    print("=" * 65)
    print("   IDS V5 — BENIGN / NORMAL TRAFFIC SIMULATOR")
    print("=" * 65)

    my_iface = get_best_iface()
    iface_desc = getattr(IFACES.get(my_iface, None), "description", my_iface)
    print(f"[*] Binding to Interface : {iface_desc}")

    try:
        gateway_ip = conf.route.route("0.0.0.0")[2]
        gateway_mac = get_gateway_mac(gateway_ip)
    except Exception:
        gateway_ip = "127.0.0.1"
        gateway_mac = "ff:ff:ff:ff:ff:ff"

    if not gateway_mac:
        gateway_mac = "ff:ff:ff:ff:ff:ff"

    print(f"[*] Gateway Resolved     : {gateway_ip} [{gateway_mac}]")

    # Target: Google LLC server IP & domain
    SERVER_IP   = "142.250.190.46"       # Resolves to Google LLC via MaxMind ASN
    DOMAIN_NAME = "www.google.com"        # Recognized TLS domain
    CLIENT_IP   = f"192.168.1.{random.randint(100, 200)}"
    HTTPS_PORT  = 443
    CLIENT_PORT = random.randint(49152, 65535)

    print(f"[*] Simulated Domain     : {DOMAIN_NAME}")
    print(f"[*] Target Server IP     : {SERVER_IP} (Google LLC)")
    print(f"[*] Client IP            : {CLIENT_IP}")
    print(f"[*] Target Port          : {HTTPS_PORT} (HTTPS)")
    print(f"[*] Expected Status      : Normal / Unflagged (Green)")
    print("-" * 65)
    print("[*] Starting normal traffic stream. Press Ctrl+C to stop.\n")

    # 1. First send TLS ClientHello with SNI to register domain in detector
    try:
        sni_pkt = (
            Ether(dst=gateway_mac)
            / IP(src=CLIENT_IP, dst=SERVER_IP)
            / TCP(sport=CLIENT_PORT, dport=HTTPS_PORT, flags="PA")
            / TLS()
            / TLSClientHello(ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=DOMAIN_NAME.encode())])])
        )
        sendp(sni_pkt, iface=my_iface, verbose=False)
    except Exception:
        pass

    # Varied realistic payloads to ensure high entropy & avoid single-payload bot rules
    sample_payloads = [
        b"GET /search?q=cybersecurity+research HTTP/1.1\r\nHost: www.google.com\r\nAccept: */*\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 1256\r\n\r\n" + (b"DATA" * 64),
        b"POST /upload HTTP/1.1\r\nHost: www.google.com\r\nContent-Length: 512\r\n\r\n" + (b"A1B2C3D4" * 32),
        b"\x17\x03\x03\x01\x00" + os.urandom(256),   # Simulated TLS Application Data
        b"\x17\x03\x03\x02\x00" + os.urandom(512),   # Simulated TLS Application Data
        b"\x17\x03\x03\x00\x80" + os.urandom(128),   # Small keep-alive frame
    ]

    total_sent = 0
    start_time = time.time()

    try:
        while True:
            # Alternating direction: Client -> Server request, Server -> Client response
            payload = random.choice(sample_payloads)
            
            if random.random() < 0.5:
                # Client to Server request
                pkt = (
                    Ether(dst=gateway_mac)
                    / IP(src=CLIENT_IP, dst=SERVER_IP)
                    / TCP(sport=CLIENT_PORT, dport=HTTPS_PORT, flags="PA")
                    / Raw(load=payload)
                )
            else:
                # Server to Client response (shows traffic originating from Google LLC)
                pkt = (
                    Ether(dst=gateway_mac)
                    / IP(src=SERVER_IP, dst=CLIENT_IP)
                    / TCP(sport=HTTPS_PORT, dport=CLIENT_PORT, flags="PA")
                    / Raw(load=payload)
                )

            sendp(pkt, iface=my_iface, verbose=False)
            total_sent += 1

            # Update simulation status every 10 packets
            if total_sent % 10 == 0:
                _update_status(f"Normal Browsing ({DOMAIN_NAME})", total_sent)
                elapsed = max(time.time() - start_time, 0.1)
                rate = total_sent / elapsed
                print(f"\r  [✓] Sent: {total_sent:,} pkts | Rate: {rate:4.1f} pkt/s | Domain: {DOMAIN_NAME} | Status: NORMAL", end="", flush=True)

            # Pacing: ~10 to 12 packets/sec (well below DoS and Bot thresholds)
            time.sleep(random.uniform(0.08, 0.12))

    except KeyboardInterrupt:
        print("\n\n[*] Stopping normal traffic simulation...")
    finally:
        _clear_status()
        print(f"[✓] Simulation ended. Total packets sent: {total_sent:,}")

if __name__ == "__main__":
    main()