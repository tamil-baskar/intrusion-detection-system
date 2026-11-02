# detector.py — Real-Time Network Intrusion Detection System V5
# U23CS704 Mini Project | Sona College of Technology

import os, sys, time, threading
from pathlib import Path
from collections import defaultdict, deque

from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw, conf, IFACES
from scapy.layers.tls.all import TLS_Ext_ServerName
import geoip2.database
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

sys.path.insert(0, str(Path(__file__).parent / "training_model"))
from ml_engine_v2 import ThreatModelManager

# ── Thresholds ────────────────────────────────────────────────────────────────
TIME_WINDOW              = 5.0    # sliding window (seconds)
INACTIVITY_TIMEOUT       = 15.0   # evict idle IPs after N seconds
DOS_THRESHOLD            = 350    # pkt/s — Volumetric DoS trigger
PORT_SCAN_THRESHOLD      = 10     # unique ports — Port Scan trigger
INDIVIDUAL_SYN_THRESHOLD = 50     # SYN count — SYN Flood trigger
BOT_RATE_THRESHOLD       = 80     # pkt/s + uniform payload — Bot trigger
GLOBAL_DOS_THRESHOLD     = 1000   # network-wide pkt/s — DDoS macro alert
ML_MIN_RATE              = 30     # skip ML below this rate (false-positive guard)
ML_CHECK_INTERVAL        = 20     # run ML every N packets per IP

TRUSTED_ORGS    = ["Google LLC", "Meta Platforms, Inc.", "Valve Corporation",
                   "Spotify AB", "Reliance Jio Infocomm Limited"]
TRUSTED_DOMAINS = ["googlevideo.com", "whatsapp.net", "steampowered.com"]

# ── Global State ──────────────────────────────────────────────────────────────
tracker = defaultdict(lambda: {
    "total_packets": 0, "display_rate": 0, "ports": set(),
    "syn_count": 0, "payload_sizes": defaultdict(int),
    "last_seen": time.time(), "alerts": [], "snis": set(),
})
global_stats = {
    "total_packets": 0, "syn_count": 0,
    "packets_this_second": 0, "last_second_time": time.time(),
    "current_pps": 0, "avg_latency_ms": 0.0, "total_latency_ms": 0.0,
}
pps_history   = deque(maxlen=120)          # 60-second traffic history
ip_first_seen : dict = {}
ui_state      = {"mode": "dashboard", "selected_idx": 0,
                 "selected_ip": None, "display_list": []}
ui_lock       = threading.Lock()
start_time    = time.time()
resolved_names: dict = {}
console       = Console(force_terminal=True, highlight=False)
ml_detector   = ThreatModelManager(mode="ensemble")

try:    asn_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")
except: asn_reader = None

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_ip_order(ip):
    if ip not in ip_first_seen: ip_first_seen[ip] = len(ip_first_seen)
    return ip_first_seen[ip]

def get_ip_identity(ip):
    if ip in resolved_names: return resolved_names[ip]
    identity = ip
    if ip.startswith(("192.168.", "10.", "127.")): identity = f"{ip} (Local/Private)"
    elif asn_reader:
        try: identity = f"{ip} ({asn_reader.asn(ip).autonomous_system_organization})"
        except: pass
    resolved_names[ip] = identity
    return identity

def log_alert(name, src=None, detail=None):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open("alerts.log", "a", encoding="utf-8") as f:
        f.write(f"[{ts}] [ALERT] {name}"
                + (f" | {get_ip_identity(src)}" if src else "")
                + (f" | {detail}" if detail else "") + "\n")

def check_window(now=None):
    global start_time
    now = now or time.time()
    if now - global_stats["last_second_time"] >= 1.0:
        global_stats["current_pps"]    = global_stats["packets_this_second"]
        global_stats["avg_latency_ms"] = global_stats["total_latency_ms"] / max(global_stats["packets_this_second"], 1)
        global_stats["packets_this_second"] = global_stats["total_latency_ms"] = 0
        global_stats["last_second_time"] = now
    if now - start_time >= TIME_WINDOW:
        for ip in list(tracker):
            if now - tracker[ip]["last_seen"] > INACTIVITY_TIMEOUT: del tracker[ip]
            else:
                tracker[ip].update({"display_rate": tracker[ip]["total_packets"],
                                    "total_packets": 0, "syn_count": 0})
                tracker[ip]["ports"].clear(); tracker[ip]["payload_sizes"].clear()
                tracker[ip]["alerts"].clear()
        global_stats.update({"syn_count": 0, "total_packets": 0})
        start_time = now

# ── Core Detection (process_packet) ──────────────────────────────────────────
def process_packet(pkt):
    now = time.time()
    global_stats["total_latency_ms"]    += (now - float(pkt.time)) * 1000
    global_stats["packets_this_second"] += 1
    check_window(now)
    if IP not in pkt and IPv6 not in pkt: return

    src = pkt[IP].src if IP in pkt else pkt[IPv6].src
    dst = pkt[IP].dst if IP in pkt else pkt[IPv6].dst
    tracker[src]["total_packets"] += 1
    tracker[src]["last_seen"]      = now
    global_stats["total_packets"] += 1

    # Deep Packet Inspection — TLS SNI extraction
    if pkt.haslayer(TLS_Ext_ServerName):
        try: tracker[dst]["snis"].add(
            pkt[TLS_Ext_ServerName].servernames[0].servername.decode())
        except: pass

    # Trust check (ASN whitelist + SNI domain whitelist)
    ident      = get_ip_identity(src)
    is_trusted = any(o in ident for o in TRUSTED_ORGS) or \
                 any(any(d in s for d in TRUSTED_DOMAINS) for s in tracker[dst]["snis"])

    # TCP heuristic rules
    if TCP in pkt:
        tracker[src]["ports"].add(pkt[TCP].dport)
        f = pkt[TCP].flags
        if src == dst and "LAND Attack" not in tracker[src]["alerts"]:
            tracker[src]["alerts"].append("LAND Attack")
            log_alert("LAND Attack", src, "src==dst (spoofed loopback)")
        if f & 0x29 == 0x29 and "XMAS Scan" not in tracker[src]["alerts"]:
            tracker[src]["alerts"].append("XMAS Scan")
            log_alert("XMAS Scan", src, "FIN+PSH+URG flags")
        if int(f) == 0 and "NULL Scan" not in tracker[src]["alerts"]:
            tracker[src]["alerts"].append("NULL Scan")
            log_alert("NULL Scan", src, "Zero TCP flags")
        if "S" in f:
            tracker[src]["syn_count"] += 1; global_stats["syn_count"] += 1
            if tracker[src]["syn_count"] > INDIVIDUAL_SYN_THRESHOLD \
                    and "SYN Flood" not in tracker[src]["alerts"]:
                tracker[src]["alerts"].append("SYN Flood")
                log_alert("SYN Flood", src, f"{tracker[src]['syn_count']} SYNs")
    elif UDP in pkt:
        tracker[src]["ports"].add(pkt[UDP].dport)
    if Raw in pkt:
        tracker[src]["payload_sizes"][len(pkt[Raw].load)] += 1

    rate = tracker[src]["total_packets"]

    # ML Ensemble prediction (LightGBM + Autoencoder)
    if not is_trusted and ml_detector.is_trained \
            and rate >= ML_MIN_RATE and rate % ML_CHECK_INTERVAL == 0:
        fv = ml_detector.extract_features(
            rate, len(tracker[src]["ports"]),
            tracker[src]["syn_count"], tracker[src]["payload_sizes"])
        if ml_detector.predict(fv) and "ML Anomaly" not in tracker[src]["alerts"]:
            tracker[src]["alerts"].append("ML Anomaly")
            log_alert("ML Anomaly", src, f"Ensemble | rate={rate}")

    # Static rate-based heuristics
    if len(tracker[src]["ports"]) >= PORT_SCAN_THRESHOLD \
            and "Port Scan" not in tracker[src]["alerts"]:
        tracker[src]["alerts"].append("Port Scan"); log_alert("Port Scan", src)
    if rate > DOS_THRESHOLD and not is_trusted \
            and "Volumetric DoS" not in tracker[src]["alerts"]:
        tracker[src]["alerts"].append("Volumetric DoS")
        log_alert("Volumetric DoS", src, f"{rate} pkt/s")
    if rate > BOT_RATE_THRESHOLD and len(tracker[src]["payload_sizes"]) == 1 \
            and not is_trusted and "Automated Bot" not in tracker[src]["alerts"]:
        tracker[src]["alerts"].append("Automated Bot")
        log_alert("Automated Bot", src, "Uniform payload")

# ── Dashboard ─────────────────────────────────────────────────────────────────
def _graph() -> Panel:
    h = list(pps_history); peak = max(h) if h else 0; samples = h[-60:] or [0]
    chart = ["".join("#" if v >= (r/_ROWS)*peak and peak else " "
                     for v in samples) for r in range(4, 0, -1)]
    chart.append("-" * len(samples))
    t = Text()
    t.append("TRAFFIC  LAST 60s\n", style="bold cyan")
    t.append(f"Current : {h[-1] if h else 0:.0f}  Peak : {peak:.0f}  "
             f"Avg : {sum(h)/len(h) if h else 0:.1f} pkt/s\n\n", style="cyan")
    for l in chart: t.append(l + "\n", style="cyan")
    return Panel(t, border_style="dim cyan", padding=(0,1))

_ROWS = 4

def _top_ips() -> Panel:
    top = sorted([(ip, tracker[ip]["display_rate"]) for ip in tracker
                  if tracker[ip]["display_rate"] > 0], key=lambda x:-x[1])[:5]
    t = Text(); t.append("TOP ACTIVE IPs\n", style="bold cyan")
    mx = max((r for _,r in top), default=1)
    for ip, r in top:
        t.append(f"{get_ip_identity(ip)[:20]:<20} ", style="bold red" if tracker[ip]["alerts"] else "green")
        t.append(f"{'#'*int(r/mx*14):<14} {r}\n", style="cyan")
    return Panel(t, border_style="dim cyan", padding=(0,1))

def generate_table():
    from rich.console import Group
    check_window(); pps_history.append(global_stats["current_pps"])
    rows = []
    for ip in tracker:
        d = tracker[ip]
        if d["display_rate"] > 0 or d["alerts"]:
            name = get_ip_identity(ip)
            if d["snis"]: name += f" [{', '.join(list(d['snis'])[:1])}]"
            rows.append({"ip": ip,
                "name":   f"[bold red][!] {name}[/bold red]" if d["alerts"] else f"    {name}",
                "rate":   str(d["display_rate"]),
                "ports":  ", ".join(map(str, list(d["ports"])[:3])) or "None",
                "status": ", ".join(d["alerts"]) if d["alerts"] else "[green]Normal[/green]"})
    rows.sort(key=lambda x: get_ip_order(x["ip"]))
    with ui_lock:
        ui_state["display_list"] = [r["ip"] for r in rows]
        idx = ui_state["selected_idx"]

    tbl = Table(title=f"[bold cyan]ACTIVE SESSIONS ({len(rows)})[/bold cyan]",
                header_style="bold cyan", width=min(console.width, 160))
    tbl.add_column("Source IP / Identity", width=55)
    tbl.add_column("Rate", justify="right", width=10)
    tbl.add_column("Ports", justify="right", width=14)
    tbl.add_column("Alert Status", width=40)
    for i, r in enumerate(rows):
        sel = ui_state["mode"] == "dashboard" and i == idx
        rv  = lambda v: f"[reverse]{v}[/reverse]" if sel else v
        tbl.add_row(rv(r["name"]), rv(r["rate"]), rv(r["ports"]), rv(r["status"]))

    hdr = Text("REAL-TIME THREAT DASHBOARD V5 — IDS", style="bold cyan", justify="center")
    tel = Text.from_markup(
        f"[yellow]Telemetry:[/yellow] PPS:[cyan]{global_stats['current_pps']}[/cyan]"
        f"  Latency:[cyan]{global_stats['avg_latency_ms']:.2f}ms[/cyan]"
        f"  ML:[{'green' if ml_detector.is_trained else 'yellow'}]"
        f"{'Active' if ml_detector.is_trained else 'Standby'}[/]"
        f"\n[dim]up/down select | Enter=details | Q=quit[/dim]")
    return Group(hdr, Columns([_graph(), _top_ips()], equal=True, expand=True), tel, tbl)

# ── Keyboard Thread ───────────────────────────────────────────────────────────
def _kbd():
    try: import msvcrt
    except: return
    while True:
        try:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                with ui_lock:
                    lst = ui_state["display_list"]; idx = ui_state["selected_idx"]; n = len(lst)
                    if ch == "\x1b": ui_state.update({"mode":"dashboard","selected_ip":None})
                    elif ch in "qQ": os._exit(0)
                    elif ch == "\r" and n > 0:
                        ui_state.update({"mode":"detail","selected_ip":lst[min(idx,n-1)]})
                    elif ch == "\xe0":
                        a = msvcrt.getwch()
                        if a == "H": ui_state["selected_idx"] = max(0, idx-1)
                        elif a == "P": ui_state["selected_idx"] = min(max(n-1,0), idx+1)
            time.sleep(0.05)
        except: time.sleep(0.1)

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    iface = conf.route.route("8.8.8.8")[0]
    console.print(f"[green][*] IDS V5 starting on {iface}[/green]")
    threading.Thread(target=lambda: sniff(iface=iface, prn=process_packet, store=False), daemon=True).start()
    threading.Thread(target=_kbd, daemon=True).start()
    try:
        with Live(generate_table(), refresh_per_second=2, console=console, screen=True) as live:
            while True:
                time.sleep(0.5); live.update(generate_table())
    except KeyboardInterrupt:
        console.print("[yellow][*] Stopped.[/yellow]")
