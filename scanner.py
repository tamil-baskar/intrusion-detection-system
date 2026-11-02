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
fake_ip = f"172.16.0.{random.randint(1, 254)}"

print(f"[*] Starting simulated Port Scan on {TARGET_IP}...")
print(f"[*] SCANNER IDENTITY SPOOFED AS: {fake_ip}")
print("[*] Scanning ports 20 through 70...")

try:
    while True:
        for port in range(20, 71):
            packet = Ether(dst=gateway_mac) / IP(src=fake_ip, dst=TARGET_IP) / UDP(dport=port) / b"Probe"
            sendp(packet, iface=my_iface, verbose=False)
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Scanner stopped.")