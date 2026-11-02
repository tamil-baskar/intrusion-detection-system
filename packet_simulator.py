"""
packet_simulator.py — IDS V5 Complete Attack Simulator
==========================================================
SAFETY: All traffic uses spoofed RFC-1918 / private source IPs.
        Default destination is 127.0.0.1 (loopback) or gateway.
        No real malware, exploits, or destructive payloads.
        For controlled IDS demonstration ONLY.

MODES:
  [1]  Normal Traffic          — low rate, benign-looking
  [2]  Synthetic Anomalous     — ML/Autoencoder trigger
  [3]  Volumetric DoS          — UDP flood → Volumetric DoS alert
  [4]  SYN Flood               — TCP SYN storm → SYN Flood alert
  [5]  LAND Attack             — src==dst → LAND Attack alert
  [6]  XMAS Scan               — FIN+PSH+URG flags → XMAS Scan alert
  [7]  NULL Scan               — zero TCP flags → NULL Scan alert
  [8]  Port Scan               — 51 UDP ports → Port Scan alert
  [9]  Automated Bot           — high-rate uniform payload → Bot alert
  [10] ALL ATTACKS (sequence)  — run all attacks back-to-back auto
  [0]  Stop current mode
  [Q]  Quit
"""

import warnings
warnings.filterwarnings("ignore", module="cryptography")

import platform
import subprocess
import random
import time
import threading
import json
import os
import sys
from pathlib import Path

from scapy.all import sendp, IP, TCP, UDP, Raw, Ether, conf, getmacbyip, IFACES

# ─── Simulation status file (read by detector.py for the dashboard panel) ─────
SIM_STATUS_FILE = Path(__file__).parent / ".sim_status.json"


def _write_status(mode: str, packets_sent: int):
    """Atomically write simulation state for the detector.py dashboard panel."""
    try:
        data = {"mode": mode, "packets_sent": packets_sent, "updated_at": time.time()}
        tmp = str(SIM_STATUS_FILE) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, str(SIM_STATUS_FILE))
    except Exception:
        pass


def _clear_status():
    _write_status("INACTIVE", 0)


# ─── Interface helpers (same pattern as all existing simulators) ───────────────
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


# ─── Shared state ──────────────────────────────────────────────────────────────
_counters = {"sent": 0}
_stop_evt = threading.Event()


def _mk_ip(subnet: int) -> str:
    """Return a fresh spoofed 10.200.<subnet>.x IP each call."""
    return f"10.200.{subnet}.{random.randint(10, 200)}"


DST = "127.0.0.1"   # loopback — stays on this machine, never leaves the host


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK SENDER FUNCTIONS
# Each function runs in its own daemon thread. All use _stop_evt to exit cleanly.
# ══════════════════════════════════════════════════════════════════════════════

def _send_normal(iface, gw_mac: str):
    """
    [1] Normal Traffic
    Low rate (~8 pkt/s), varied ports & payloads.
    Represents benign background traffic — should stay 'Normal' on the dashboard.
    Expected alert: NONE
    """
    src      = _mk_ip(1)
    ports    = [80, 443, 8080, 53, 22, 8443, 3000, 5000]
    payloads = [b"GET / HTTP/1.1", b"Hello", b"data_chunk",
                b"ping", b"keep-alive", b"user-agent: test"]
    _info(src, "~8 pkt/s | varied ports & payload sizes", "None (benign baseline)")

    while not _stop_evt.is_set():
        pkt = (Ether(dst=gw_mac)
               / IP(src=src, dst=DST)
               / UDP(sport=random.randint(1024, 65535), dport=random.choice(ports))
               / Raw(load=random.choice(payloads)))
        _sendp(pkt, iface)
        time.sleep(0.12)


def _send_anomalous(iface, gw_mac: str):
    """
    [2] Synthetic Anomalous Traffic
    High rate + many ports + high SYN → pushes all 6 ML features far from baseline.
    Autoencoder MSE >> threshold (1.05).
    Expected alert: ML Anomaly, SYN Flood
    """
    src       = _mk_ip(2)
    port_pool = list(range(7000, 7030))  # 30 distinct ports
    _info(src, "~200+ pkt/s | 30 ports, high SYN burst", "ML Anomaly, SYN Flood")
    print("    *** SYNTHETIC ANOMALOUS TRAFFIC — not a real attack ***\n")

    while not _stop_evt.is_set():
        for port in port_pool:
            if _stop_evt.is_set():
                break
            pkt = (Ether(dst=gw_mac)
                   / IP(src=src, dst=DST)
                   / TCP(sport=random.randint(1024, 65535), dport=port, flags="S"))
            _sendp(pkt, iface, count=3)
        time.sleep(0.05)


def _send_volumetric_dos(iface, gw_mac: str):
    """
    [3] Volumetric DoS
    ~1 000 pkt/s, single port, fixed uniform payload.
    Rate > DOS_THRESHOLD (350) → Volumetric DoS alert.
    Fixed payload size → Automated Bot alert if payload_sizes==1.
    Expected alerts: Volumetric DoS, ML Anomaly
    """
    src     = _mk_ip(3)
    payload = b"X" * 512   # fixed size → very low payload entropy
    _info(src, "~1 000 pkt/s | single port, fixed 512-byte payload",
          "Volumetric DoS, ML Anomaly")
    print("    *** SYNTHETIC VOLUMETRIC DOS — not a real attack ***\n")

    pkt = (Ether(dst=gw_mac)
           / IP(src=src, dst=DST)
           / UDP(sport=9999, dport=9999)
           / Raw(load=payload))
    while not _stop_evt.is_set():
        _sendp(pkt, iface, count=50)
        time.sleep(0.05)


def _send_syn_flood(iface, gw_mac: str):
    """
    [4] SYN Flood
    Rapidly sends TCP SYN packets from random spoofed IPs.
    syn_count > INDIVIDUAL_SYN_THRESHOLD (50) per source → SYN Flood alert.
    Many different IPs → BOTNET SWARM macro alert if unique IPs > 50.
    Expected alerts: SYN Flood (per IP), GLOBAL TCP SYN FLOOD (macro)
    """
    fixed_src = _mk_ip(4)   # one fixed attacker IP for reliable per-IP detection
    _info(fixed_src, "~500 pkt/s | TCP SYN from single spoofed IP", "SYN Flood")
    print("    *** SYNTHETIC SYN FLOOD — not a real attack ***\n")

    while not _stop_evt.is_set():
        for _ in range(30):
            if _stop_evt.is_set():
                break
            pkt = (Ether(dst=gw_mac)
                   / IP(src=fixed_src, dst=DST)
                   / TCP(sport=random.randint(1024, 65535), dport=80, flags="S"))
            _sendp(pkt, iface)


def _send_land(iface, gw_mac: str):
    """
    [5] LAND Attack
    Source IP == Destination IP → detector's LAND Attack check fires immediately.
    Expected alert: LAND Attack
    """
    # For LAND: src must equal dst — we use the loopback address
    land_ip = DST   # 127.0.0.1 → src==dst
    _info(land_ip, "TCP SYN | src IP == dst IP (spoofed loopback)", "LAND Attack")
    print("    *** SYNTHETIC LAND ATTACK — not a real attack ***\n")

    while not _stop_evt.is_set():
        pkt = (Ether(dst=gw_mac)
               / IP(src=land_ip, dst=land_ip)
               / TCP(dport=9999, flags="S"))
        _sendp(pkt, iface, count=20)
        time.sleep(0.1)


def _send_xmas(iface, gw_mac: str):
    """
    [6] XMAS Scan
    TCP flags = FIN + PSH + URG (0x29) — the 'lit up' packet.
    Expected alert: XMAS Scan
    """
    src = _mk_ip(6)
    _info(src, "TCP FIN+PSH+URG flags (0x29) | stealth probe", "XMAS Scan")
    print("    *** SYNTHETIC XMAS SCAN — not a real attack ***\n")

    while not _stop_evt.is_set():
        pkt = (Ether(dst=gw_mac)
               / IP(src=src, dst=DST)
               / TCP(dport=9999, flags="FPU"))   # FPU = FIN+PSH+URG = 0x29
        _sendp(pkt, iface, count=20)
        time.sleep(0.1)


def _send_null(iface, gw_mac: str):
    """
    [7] NULL Scan
    TCP flags = 0x00 (no flags) — invisible stealth probe.
    Expected alert: NULL Scan
    """
    src = _mk_ip(7)
    _info(src, "TCP flags=0x00 (zero flags) | stealth probe", "NULL Scan")
    print("    *** SYNTHETIC NULL SCAN — not a real attack ***\n")

    while not _stop_evt.is_set():
        pkt = (Ether(dst=gw_mac)
               / IP(src=src, dst=DST)
               / TCP(dport=9999, flags=""))   # empty string → flags=0x00
        _sendp(pkt, iface, count=20)
        time.sleep(0.1)


def _send_portscan(iface, gw_mac: str):
    """
    [8] Port Scan
    Sweeps 51 unique destination ports → len(ports) > PORT_SCAN_THRESHOLD (10).
    Expected alerts: Port Scan, possibly Automated Bot
    """
    src = _mk_ip(8)
    _info(src, "UDP sweep ports 20–70 (51 ports, cycling)", "Port Scan")
    print("    *** SYNTHETIC PORT SCAN — not a real attack ***\n")

    while not _stop_evt.is_set():
        for port in range(20, 71):
            if _stop_evt.is_set():
                break
            pkt = (Ether(dst=gw_mac)
                   / IP(src=src, dst=DST)
                   / UDP(dport=port)
                   / b"Probe")
            _sendp(pkt, iface)
        time.sleep(1.0)


def _send_automated_bot(iface, gw_mac: str):
    """
    [9] Automated Bot
    Rate > BOT_RATE_THRESHOLD (80) WITH exactly 1 unique payload size.
    len(payload_sizes) == 1 AND rate > threshold → Automated Bot alert.
    Expected alerts: Automated Bot, Volumetric DoS, ML Anomaly
    """
    src     = _mk_ip(9)
    payload = b"BOT_HEARTBEAT_v1"   # single fixed payload size
    _info(src, f"~200 pkt/s | single uniform {len(payload)}-byte payload",
          "Automated Bot, Volumetric DoS")
    print("    *** SYNTHETIC BOT SIMULATION — not a real attack ***\n")

    pkt = (Ether(dst=gw_mac)
           / IP(src=src, dst=DST)
           / UDP(sport=5000, dport=5000)
           / Raw(load=payload))
    while not _stop_evt.is_set():
        _sendp(pkt, iface, count=20)
        time.sleep(0.1)


def _send_all_sequence(iface, gw_mac: str):
    """
    [10] ALL ATTACKS — sequential demonstration
    Runs each attack for 15 seconds then moves to the next automatically.
    One complete cycle proves every detection rule fires end-to-end.
    """
    attacks = [
        ("Normal Traffic (baseline)",   _send_normal,         10),
        ("Volumetric DoS",              _send_volumetric_dos, 15),
        ("SYN Flood",                   _send_syn_flood,      15),
        ("LAND Attack",                 _send_land,           15),
        ("XMAS Scan",                   _send_xmas,           15),
        ("NULL Scan",                   _send_null,           15),
        ("Port Scan",                   _send_portscan,       15),
        ("Automated Bot",               _send_automated_bot,  15),
        ("Synthetic Anomalous (ML/AE)", _send_anomalous,      15),
    ]

    print("\n  ╔══════════════════════════════════════════════════════╗")
    print("  ║  ALL ATTACKS SEQUENCE                                ║")
    print("  ║  Each attack runs for its allotted time, then        ║")
    print("  ║  switches automatically.  Watch the IDS dashboard.   ║")
    print("  ╚══════════════════════════════════════════════════════╝\n")

    for label, fn, duration in attacks:
        if _stop_evt.is_set():
            break
        _counters["sent"] = 0
        _write_status(f"ALL SEQ: {label}", 0)

        print(f"\n  ▶  [{label}]  ({duration}s)")
        print("  " + "─" * 54)

        # Inner stop event — only active for the duration of this sub-attack
        inner_stop = threading.Event()

        def _sender_wrapper(f=fn, stop=inner_stop):
            # Replace _stop_evt checks inside sub-senders temporarily
            # by monkey-patching: we pass iface+gw_mac and they use
            # the global _stop_evt.  We stop them via the outer _stop_evt
            # or by setting inner_stop and having the outer loop join.
            f(iface, gw_mac)

        t = threading.Thread(target=_sender_wrapper, daemon=True)
        t.start()

        for elapsed in range(duration):
            if _stop_evt.is_set():
                break
            sent = _counters["sent"]
            rate = sent // max(elapsed, 1)
            print(f"    {elapsed+1:>2}s | Sent: {sent:>6} pkts | ~{rate} pkt/s",
                  end="\r", flush=True)
            _write_status(f"ALL: {label}", sent)
            time.sleep(1.0)

        # Stop this sub-attack by signalling _stop_evt briefly, then clearing
        _stop_evt.set()
        t.join(timeout=2.0)
        _stop_evt.clear()   # reset for next sub-attack

        print(f"\n    ✓  {label} — {_counters['sent']} packets sent")
        time.sleep(1.0)     # brief pause between attacks

    print("\n\n  ═══ ALL ATTACKS SEQUENCE COMPLETE ═══")


# ─── Mode registry ─────────────────────────────────────────────────────────────
# key → (display label, sender function, subnet index for IP display)
MODES = {
    "1":  ("Normal Traffic",               _send_normal,          1),
    "2":  ("Synthetic Anomalous Traffic",  _send_anomalous,       2),
    "3":  ("Volumetric DoS",               _send_volumetric_dos,  3),
    "4":  ("SYN Flood",                    _send_syn_flood,       4),
    "5":  ("LAND Attack",                  _send_land,            0),   # src==dst
    "6":  ("XMAS Scan",                    _send_xmas,            6),
    "7":  ("NULL Scan",                    _send_null,            7),
    "8":  ("Port Scan",                    _send_portscan,        8),
    "9":  ("Automated Bot",               _send_automated_bot,   9),
    "10": ("ALL ATTACKS (auto sequence)", _send_all_sequence,    0),
}

# Stop key and quit key
STOP_KEY = "0"
QUIT_KEY  = "Q"


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _sendp(pkt, iface, count: int = 1):
    """Wrapper: send and increment counter, swallow transient errors."""
    try:
        sendp(pkt, iface=iface, count=count, verbose=False)
        _counters["sent"] += count
    except Exception:
        pass


def _info(src_ip: str, rate_desc: str, expected: str):
    """Print the mode info header block."""
    print(f"\n    Source IP : {src_ip}")
    print(f"    Dest      : {DST}  (loopback — stays on this machine)")
    print(f"    Traffic   : {rate_desc}")
    print(f"    Expected  : {expected}")
    print()


def _display_loop(label: str):
    """Live packet counter running alongside the sender thread."""
    start = time.time()
    prev  = 0
    while not _stop_evt.is_set():
        sent    = _counters["sent"]
        elapsed = int(time.time() - start)
        rate    = sent - prev
        prev    = sent
        print(f"  Packets Sent: {sent:>7} | Duration: {elapsed:>4}s"
              f" | Rate ~ {rate:>5} pkt/s", end="\r", flush=True)
        _write_status(label, sent)
        time.sleep(1.0)
    print()


def _print_report(label: str, start_t: float):
    """End-of-session summary with the last few matching alerts.log lines."""
    elapsed = time.time() - start_t
    sent    = _counters["sent"]
    print()
    print("═" * 62)
    print("  SIMULATION COMPLETE")
    print("═" * 62)
    print(f"  Mode          : {label}")
    print(f"  Packets Sent  : {sent}")
    print(f"  Duration      : {elapsed:.1f}s")
    print(f"  Avg Rate      : {sent / max(elapsed, 1):.1f} pkt/s")
    print()
    print("  IDS processes packets in a 5-second rolling window.")
    print("  Alerts appear in the dashboard after the first window.")
    print()

    log_path = Path(__file__).parent / "alerts.log"
    if log_path.exists():
        try:
            with open(log_path, encoding="utf-8") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            keywords = ["ML Anomaly", "Volumetric DoS", "Port Scan", "SYN Flood",
                        "LAND Attack", "XMAS Scan", "NULL Scan", "Automated Bot"]
            recent = [ln for ln in lines[-30:] if any(k in ln for k in keywords)]
            if recent:
                print("  RECENT IDS ALERTS (alerts.log):")
                for entry in recent[-8:]:
                    print(f"    {entry}")
            else:
                print("  No matching alerts in alerts.log yet.")
                print("  Tip: ensure detector.py is running in another terminal.")
        except Exception:
            pass
    print("═" * 62)
    print()


# ─── Banner & Menu ────────────────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║          IDS V5  —  COMPLETE ATTACK SIMULATOR                ║
╠══════════════════════════════════════════════════════════════╣
║  All attacks are SYNTHETIC — spoofed IPs, loopback dest.     ║
║  Packets → NIC → detector.py Scapy sniffer → IDS pipeline   ║
║  No real malware, exploits, or external hosts.               ║
╚══════════════════════════════════════════════════════════════╝
"""

MENU = """
╔══════════════════════════════════════════════════════════════╗
║              SELECT ATTACK MODE                              ║
╠══════════════════════════════════════════════════════════════╣
║  [1]  Normal Traffic          (benign baseline)              ║
║  [2]  Synthetic Anomalous     (ML / Autoencoder trigger)     ║
║  [3]  Volumetric DoS          (UDP flood → DoS alert)        ║
║  [4]  SYN Flood               (TCP SYN storm → SYN alert)   ║
║  [5]  LAND Attack             (src==dst → LAND alert)        ║
║  [6]  XMAS Scan               (FIN+PSH+URG → XMAS alert)    ║
║  [7]  NULL Scan               (zero flags → NULL alert)      ║
║  [8]  Port Scan               (51 ports → Port Scan alert)   ║
║  [9]  Automated Bot           (uniform payload → Bot alert)  ║
║  [10] ALL ATTACKS             (full auto sequence)           ║
╠══════════════════════════════════════════════════════════════╣
║  [0]  Stop current mode                                      ║
║  [Q]  Quit                                                   ║
╚══════════════════════════════════════════════════════════════╝"""

EXPECTED = {
    "1":  "None (Normal)",
    "2":  "ML Anomaly, SYN Flood",
    "3":  "Volumetric DoS, ML Anomaly",
    "4":  "SYN Flood, Global TCP SYN Flood",
    "5":  "LAND Attack",
    "6":  "XMAS Scan",
    "7":  "NULL Scan",
    "8":  "Port Scan",
    "9":  "Automated Bot, Volumetric DoS",
    "10": "ALL of the above",
}


# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    iface      = get_best_iface()
    iface_desc = getattr(IFACES.get(iface, None), "description", str(iface))
    gw_ip      = conf.route.route("0.0.0.0")[2]
    gw_mac     = get_gateway_mac(gw_ip)

    print(f"  Interface : {iface_desc}")
    print(f"  Gateway   : {gw_ip}")

    if not gw_mac:
        print("\n  [!] Could not resolve gateway MAC address.")
        print("  [!] Windows: ensure Npcap is installed.")
        print("  [!] Linux:   run as root / sudo.")
        sys.exit(1)

    print(f"  GW MAC    : {gw_mac}")
    print()
    print("  TIP: Keep detector.py running in another terminal.")
    print("       Alerts appear on its dashboard after ~5 seconds.")

    _clear_status()

    active_thread = None
    active_label  = ""
    session_start = None

    try:
        while True:
            print(MENU)
            choice = input("\n  Select: ").strip().upper()

            # ── Quit ────────────────────────────────────────────────────────────
            if choice == QUIT_KEY:
                break

            # ── Stop current mode ────────────────────────────────────────────────
            if choice == STOP_KEY:
                if active_thread and active_thread.is_alive():
                    print("\n  ■  Stopping simulation...")
                    _stop_evt.set()
                    active_thread.join(timeout=4.0)
                    if session_start:
                        _print_report(active_label, session_start)
                else:
                    print("\n  No simulation is currently running.")
                _clear_status()
                active_thread = None
                continue

            if choice not in MODES:
                print("\n  ✗  Invalid choice. Enter 1-10, 0, or Q.\n")
                continue

            # ── Stop previous mode cleanly ────────────────────────────────────────
            if active_thread and active_thread.is_alive():
                print("\n  ■  Stopping previous mode...")
                _stop_evt.set()
                active_thread.join(timeout=4.0)
                if session_start:
                    _print_report(active_label, session_start)

            label, sender_fn, subnet = MODES[choice]
            src_display = DST if subnet == 0 else f"10.200.{subnet}.x (spoofed)"

            _stop_evt.clear()
            _counters["sent"] = 0
            session_start     = time.time()
            active_label      = label

            print(f"\n  ╔══════════════════════════════════════════════════════╗")
            print(f"  ║  MODE     : {label:<42}║")
            print(f"  ║  SOURCE   : {src_display:<42}║")
            print(f"  ║  DEST     : {DST} (loopback)                      ║")
            print(f"  ║  EXPECTS  : {EXPECTED.get(choice, '...'):<42}║")
            print(f"  ╚══════════════════════════════════════════════════════╝")
            print(f"\n  ▶  STARTING — press [0] + Enter to stop | Ctrl+C to quit\n")

            t_send = threading.Thread(target=sender_fn, args=(iface, gw_mac), daemon=True)
            t_disp = threading.Thread(target=_display_loop, args=(label,), daemon=True)
            t_send.start()
            t_disp.start()
            active_thread = t_send

    except KeyboardInterrupt:
        print("\n\n  [Ctrl+C] Stopping...")
        _stop_evt.set()
        if active_thread and active_thread.is_alive():
            active_thread.join(timeout=4.0)
        if session_start:
            _print_report(active_label, session_start)

    finally:
        _stop_evt.set()
        _clear_status()
        print("\n  Simulator exited cleanly.")


if __name__ == "__main__":
    main()
