import os
import sys

# ── Force Windows console to UTF-8 (code page 65001) BEFORE any rich output ──
# This must happen at the very top so sys.stdout.encoding reflects UTF-8
# before the Console object and _GRAPH_CHARS probe are created.
if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw, load_layer, IFACES, conf
from scapy.layers.tls.all import TLS_Ext_ServerName
import time
import geoip2.database
from collections import defaultdict, deque
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
import threading
import json
from pathlib import Path

# Add training_model folder to sys.path so ml_engine_v2 can be imported cleanly
_training_model_dir = Path(__file__).parent / "training_model"
if str(_training_model_dir) not in sys.path:
    sys.path.insert(0, str(_training_model_dir))

from ml_engine_v2 import ThreatModelManager


def get_best_iface():
    """Use the OS routing table to find the interface for internet traffic.
    conf.route.route() is authoritative and deterministic — no dict ordering issues."""
    try:
        iface_name, _, _ = conf.route.route("8.8.8.8")
        return iface_name
    except Exception:
        # Fall back: first interface with a real routable IP
        for guid, iface in IFACES.items():
            ip = getattr(iface, 'ip', '') or ''
            if ip and ip != '127.0.0.1' and not ip.startswith('169.254.'):
                return guid
        return conf.iface

# --- V5 Upgraded Lab Parameters ---
def log_alert(alert_name, src_ip=None, details=None):
    """Writes alerts with timestamp, attacker IP/identity, and event details to alerts.log."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    ip_info = f" | Source: {get_ip_identity(src_ip)}" if src_ip else ""
    extra = f" | Details: {details}" if details else ""
    log_line = f"[{timestamp}] [ALERT] {alert_name}{ip_info}{extra}\n"
    with open("alerts.log", "a", encoding="utf-8") as f:
        f.write(log_line)

ml_detector = ThreatModelManager(mode="ensemble") 

TIME_WINDOW = 5.0        
INACTIVITY_TIMEOUT = 15.0  
ASN_DB_PATH = "GeoLite2-ASN.mmdb"  

DOS_THRESHOLD = 350            # Raised: router at 201 was triggering false positives
PORT_SCAN_THRESHOLD = 10       
INDIVIDUAL_SYN_THRESHOLD = 50  
BOT_RATE_THRESHOLD = 80        # Min packets/window of identical payload to flag automated bot
GLOBAL_DOS_THRESHOLD = 1000    
SWARM_THRESHOLD = 50           # Increased from 20 to prevent false alarms on busy Wi-Fi networks
GLOBAL_SYN_THRESHOLD = 300     
ML_MIN_RATE = 30               # Skip ML prediction below this rate — avoids false positives
                               # from low-volume local traffic (router heartbeats, etc.)
ML_CHECK_INTERVAL = 20         # Run ML every N packets (was 10) to reduce chatty alerts

TRUSTED_ORGS = [
    "Google LLC", "Meta Platforms, Inc.", "Facebook, Inc.", 
    "Valve Corporation", "Spotify AB", "Reliance Jio Infocomm Limited" , "Bharati Airtel"
]

TRUSTED_DOMAINS = [
    "googlevideo.com", "whatsapp.net", "whatsapp.com",
    "steampowered.com", "spotify.com", "hoyoverse.com"
]

load_layer("tls")

tracker = defaultdict(lambda: {
    'total_packets': 0, 'display_rate': 0, 'ports': set(), 
    'syn_count': 0, 'payload_sizes': defaultdict(int),
    'land_count': 0, 'xmas_count': 0, 'null_count': 0,
    'last_seen': time.time(), 'alerts': [], 'snis': set() 
})

global_stats = {
    'total_packets': 0, 'syn_count': 0, 
    'packets_this_second': 0, 'last_second_time': time.time(), 'current_pps': 0,
    'total_latency_ms': 0.0, 'avg_latency_ms': 0.0 
}

start_time = time.time()
resolved_names = {}

# Console: force_terminal so rich doesn't strip styles in non-TTY contexts.
# No need to reconfigure stdout again — already done at top of file.
console = Console(force_terminal=True, highlight=False)

# Tracks the order each IP was first seen — used to keep table rows stable
# (new IPs append to the bottom; existing rows never jump positions).
ip_first_seen: dict[str, int] = {}

# ─── NEW: Traffic history for the sparkline graph ──────────────────────────────
# Rolling 60 samples at 0.5s refresh = ~30 seconds of visible history
TRAFFIC_HISTORY_MAX = 120   # 120 × 0.5s = 60 seconds
pps_history: deque = deque(maxlen=TRAFFIC_HISTORY_MAX)

# ─── NEW: Interactive state ─────────────────────────────────────────────────────
ui_state = {
    "mode": "dashboard",       # "dashboard" | "detail"
    "selected_idx": 0,         # index into sorted display_data
    "selected_ip": None,       # IP string when in detail mode
    "display_list": [],        # list of ip strings in table order (updated each render)
}
ui_lock = threading.Lock()



def get_ip_order(ip: str) -> int:
    """Return a stable sort index for `ip`, assigning a new one on first sight."""
    if ip not in ip_first_seen:
        ip_first_seen[ip] = len(ip_first_seen)
    return ip_first_seen[ip]

try:
    asn_reader = geoip2.database.Reader(ASN_DB_PATH)
except FileNotFoundError:
    console.print(f"[bold red][!] Could not find {ASN_DB_PATH}. ASN lookups disabled.[/bold red]")
    asn_reader = None

def get_ip_identity(ip):
    if ip in resolved_names:
        return resolved_names[ip]
    
    identity = ip
    if ip.startswith("192.168.") or ip.startswith("10.") or "fe80:" in ip or ip == "127.0.0.1" or ip == "::1":
        identity = f"{ip} (Local/Private)"
    elif asn_reader:
        try:
            response = asn_reader.asn(ip)
            org = response.autonomous_system_organization
            identity = f"{ip} ({org})"
        except Exception:
            pass 
            
    resolved_names[ip] = identity
    return identity

def check_window_expiration(current_time=None):
    global start_time, tracker, global_stats
    if current_time is None:
        current_time = time.time()

    if current_time - global_stats['last_second_time'] >= 1.0:
        global_stats['current_pps'] = global_stats['packets_this_second']
        if global_stats['packets_this_second'] > 0:
            global_stats['avg_latency_ms'] = global_stats['total_latency_ms'] / global_stats['packets_this_second']
        else:
            global_stats['avg_latency_ms'] = 0.0
            
        global_stats['packets_this_second'] = 0
        global_stats['total_latency_ms'] = 0.0
        global_stats['last_second_time'] = current_time

    if current_time - start_time >= TIME_WINDOW:
        for ip in list(tracker.keys()):
            if current_time - tracker[ip]['last_seen'] > INACTIVITY_TIMEOUT:
                del tracker[ip]
            else:
                tracker[ip]['display_rate'] = tracker[ip]['total_packets']
                tracker[ip]['total_packets'] = 0
                tracker[ip]['syn_count'] = 0
                tracker[ip]['ports'].clear()
                tracker[ip]['payload_sizes'].clear()
                tracker[ip]['alerts'].clear()
                
        global_stats['syn_count'] = 0
        global_stats['total_packets'] = 0
        start_time = current_time


# ─── FEATURE HELPERS (reuse ml_engine_v2 logic exactly) ───────────────────────
def _get_ip_features(ip: str) -> dict:
    """Extract the 6 ML features for an IP from the existing tracker state.
    Single source of truth — never duplicates calculation."""
    data = tracker.get(ip)
    if data is None:
        return None
    rate        = float(data['display_rate'])
    ports_count = float(len(data['ports']))
    syn_count   = float(data['syn_count'])
    safe_rate   = max(rate, 1.0)
    from ml_engine_v2 import calculate_entropy
    payload_entropy = calculate_entropy(data['payload_sizes'])
    syn_ratio       = syn_count / safe_rate
    port_diversity  = ports_count / safe_rate
    return {
        "rate": rate,
        "ports_count": ports_count,
        "syn_count": syn_count,
        "payload_entropy": payload_entropy,
        "syn_ratio": syn_ratio,
        "port_diversity": port_diversity,
    }


# ─── GRAPH RENDERER ────────────────────────────────────────────────────────────
# Unicode block chars — safe to use now that chcp 65001 was called at startup.
# If for some reason the terminal still can't handle them, fall back gracefully.
_UNICODE_BARS = " \u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
try:
    _UNICODE_BARS.encode(sys.stdout.encoding or "utf-8")
    _GRAPH_CHARS = _UNICODE_BARS
except (UnicodeEncodeError, LookupError):
    # Visible ASCII fallback — still shows relative heights
    _GRAPH_CHARS = " _.-:=|II"

def _render_graph() -> Panel:
    """Build a Unicode sparkline traffic graph from pps_history."""
    history = list(pps_history)
    current = history[-1] if history else 0
    peak    = max(history) if history else 0
    avg     = (sum(history) / len(history)) if history else 0

    # Build sparkline
    if peak > 0:
        bars = ""
        for v in history[-60:]:              # show last 60 samples
            idx = int((v / peak) * (len(_GRAPH_CHARS) - 1))
            idx = max(0, min(idx, len(_GRAPH_CHARS) - 1))
            bars += _GRAPH_CHARS[idx]
    else:
        bars = _GRAPH_CHARS[0] * min(60, len(history)) if history else "─" * 30

    graph_text = Text()
    graph_text.append("TRAFFIC — LAST 60s\n", style="bold cyan")
    graph_text.append(f"Current : ", style="dim")
    graph_text.append(f"{current:.0f} pkt/s\n", style="yellow")
    graph_text.append(f"Peak    : ", style="dim")
    graph_text.append(f"{peak:.0f} pkt/s\n", style="red" if peak > DOS_THRESHOLD else "green")
    graph_text.append(f"Average : ", style="dim")
    graph_text.append(f"{avg:.1f} pkt/s\n\n", style="cyan")
    graph_text.append(bars, style="cyan")

    return Panel(graph_text, border_style="dim cyan", padding=(0, 1))


# ─── TOP ACTIVE IPS PANEL ──────────────────────────────────────────────────────
def _render_top_ips() -> Panel:
    """Build a bar-chart panel of the top 5 IPs by display_rate."""
    candidates = [
        (ip, tracker[ip]['display_rate'])
        for ip in tracker
        if tracker[ip]['display_rate'] > 0 or tracker[ip]['alerts']
    ]
    candidates.sort(key=lambda x: x[1], reverse=True)
    top5 = candidates[:5]

    text = Text()
    text.append("TOP ACTIVE IPs\n", style="bold cyan")
    if not top5:
        text.append("No active traffic\n", style="dim")
    else:
        max_rate = max(r for _, r in top5) if top5 else 1
        for ip, rate in top5:
            identity = get_ip_identity(ip)
            # Truncate identity to 22 chars
            label = identity[:22].ljust(22)
            bar_len = int((rate / max(max_rate, 1)) * 14)
            bar = "█" * bar_len
            is_sus = bool(tracker[ip]['alerts'])
            ip_style = "bold red" if is_sus else "green"
            text.append(f"{label} ", style=ip_style)
            text.append(f"{bar:<14} ", style="cyan")
            text.append(f"{rate}\n", style="yellow")

    return Panel(text, border_style="dim cyan", padding=(0, 1))


# ─── DETAIL PANEL ──────────────────────────────────────────────────────────────
def _render_detail_panel(ip: str) -> Panel:
    """Build the full Threat Details panel for the selected IP.
    All values come directly from tracker[] — single source of truth."""
    data = tracker.get(ip)
    if data is None:
        txt = Text()
        txt.append(f"IP {ip} is no longer active (cleaned up by inactivity timeout).\n", style="yellow")
        txt.append("\n[ESC] Back  [Q] Quit", style="dim")
        return Panel(txt, title="[bold red]THREAT DETAILS[/bold red]", border_style="red")

    feats = _get_ip_features(ip)
    if feats is None:
        feats = {"rate": 0, "ports_count": 0, "syn_count": 0,
                 "payload_entropy": 0.0, "syn_ratio": 0.0, "port_diversity": 0.0}

    identity  = get_ip_identity(ip)
    alerts    = list(data['alerts'])
    is_sus    = bool(alerts)
    sni_str   = ", ".join(list(data['snis'])[:3]) if data['snis'] else "N/A"
    status    = "SUSPICIOUS" if is_sus else "NORMAL"

    # Check trusted status (identical to process_packet)
    is_trusted = False
    trusted_reason = None
    if asn_reader and ip:
        try:
            resp = asn_reader.asn(ip)
            org = resp.autonomous_system_organization
            if org in TRUSTED_ORGS:
                is_trusted = True
                trusted_reason = org
        except Exception:
            pass
    if not is_trusted:
        for sni in data['snis']:
            if any(trusted in sni for trusted in TRUSTED_DOMAINS):
                is_trusted = True
                trusted_reason = sni
                break

    # ML eligibility: In process_packet(), ML is only evaluated if not is_trusted and rate >= ML_MIN_RATE.
    # Evaluating ML on low-rate traffic (e.g. 1 pkt/s mDNS/DNS) produces false Autoencoder reconstruction spikes.
    rate = feats["rate"]
    ml_eligible = (not is_trusted) and (rate >= ML_MIN_RATE)

    # ML scores
    ml_scores = {"lgbm": {"prob": None, "flagged": False},
                 "ae": {"mse": None, "threshold": None, "flagged": False}}
    if ml_detector.is_trained:
        try:
            feat_vec = ml_detector.extract_features(
                feats["rate"], feats["ports_count"], feats["syn_count"], data['payload_sizes']
            )
            raw_scores = ml_detector.predict_detailed(feat_vec)
            if ml_eligible:
                ml_scores = raw_scores
            else:
                # Keep numeric values for display, but DO NOT flag when ineligible (trusted or rate < 30)
                ml_scores["lgbm"]["prob"] = raw_scores["lgbm"]["prob"]
                ml_scores["ae"]["mse"] = raw_scores["ae"]["mse"]
                ml_scores["ae"]["threshold"] = raw_scores["ae"]["threshold"]
                ml_scores["lgbm"]["flagged"] = False
                ml_scores["ae"]["flagged"] = False
        except Exception:
            pass

    lgbm_prob  = ml_scores["lgbm"]["prob"]
    ae_mse     = ml_scores["ae"]["mse"]
    ae_thresh  = ml_scores["ae"]["threshold"]
    lgbm_flag  = ml_scores["lgbm"]["flagged"]
    ae_flag    = ml_scores["ae"]["flagged"]

    # Heuristic flags
    HEURISTIC_ALERTS = {"LAND Attack", "XMAS Scan", "NULL Scan", "SYN Flood",
                        "Port Scan", "Volumetric DoS", "Automated Bot"}
    heuristic_triggered = [a for a in alerts if a in HEURISTIC_ALERTS]
    ml_triggered        = [a for a in alerts if a == "ML Anomaly"]

    # Detection source
    has_heur  = bool(heuristic_triggered)
    has_lgbm  = lgbm_flag
    has_ae    = ae_flag
    sources   = []
    if has_heur:  sources.append("HEURISTIC")
    if has_lgbm:  sources.append("LIGHTGBM")
    if has_ae:    sources.append("AUTOENCODER")
    detection_source = " + ".join(sources) if sources else "NONE"

    # Final verdict
    if not is_sus:
        verdict = "[bold green]NORMAL[/bold green]"
    elif len(sources) > 2:
        verdict = "[bold red]MULTIPLE THREATS[/bold red]"
    elif "ML Anomaly" in alerts and not has_heur:
        if has_lgbm and has_ae:
            verdict = "[bold red]LGBM + AUTOENCODER ANOMALY[/bold red]"
        elif has_lgbm:
            verdict = "[bold red]ML ANOMALY (LightGBM)[/bold red]"
        elif has_ae:
            verdict = "[bold red]ML ANOMALY (Autoencoder)[/bold red]"
        else:
            verdict = "[bold red]ML ANOMALY[/bold red]"
    elif heuristic_triggered:
        verdict = f"[bold red]{', '.join(heuristic_triggered)}[/bold red]"
    else:
        verdict = "[bold red]SUSPICIOUS[/bold red]"

    # WHY FLAGGED section
    reasons = []
    if "SYN Flood" in alerts:
        reasons.append(f"✓ SYN count ({feats['syn_count']:.0f}) exceeded threshold ({INDIVIDUAL_SYN_THRESHOLD})")
    if "Port Scan" in alerts:
        reasons.append(f"✓ Unique destination ports ({feats['ports_count']:.0f}) exceeded threshold ({PORT_SCAN_THRESHOLD})")
    if "Volumetric DoS" in alerts:
        reasons.append(f"✓ Packet rate ({feats['rate']:.0f} pkt/s) exceeded threshold ({DOS_THRESHOLD})")
    if "Automated Bot" in alerts:
        reasons.append(f"✓ Rate {feats['rate']:.0f} pkt/s with static uniform payload")
    if "LAND Attack" in alerts:
        reasons.append("✓ LAND Attack — Source IP equals Destination IP (spoofed loopback)")
    if "XMAS Scan" in alerts:
        reasons.append("✓ XMAS Scan — TCP FIN+PSH+URG flags set simultaneously")
    if "NULL Scan" in alerts:
        reasons.append("✓ NULL Scan — TCP packet with zero flags")
    if ml_eligible:
        if ae_flag and ae_mse is not None and ae_thresh is not None:
            reasons.append(f"✓ Autoencoder reconstruction error (MSE {ae_mse:.4f}) exceeded threshold ({ae_thresh:.4f})")
        if lgbm_flag and lgbm_prob is not None:
            reasons.append(f"✓ LightGBM threat probability ({lgbm_prob:.2f}) exceeded threshold (0.50)")
        if feats['syn_ratio'] > 0.4 and "SYN Flood" not in alerts:
            reasons.append(f"✓ High SYN ratio ({feats['syn_ratio']:.2f}) — elevated handshake initiation rate")
    if not reasons:
        reasons.append("✗ No threat indicators active")
        if is_trusted:
            reasons.append(f"• Verified trusted entity ({trusted_reason})")
        elif rate < ML_MIN_RATE:
            reasons.append(f"• Low-volume background traffic (Rate {rate:.0f} < {ML_MIN_RATE} pkt/s threshold)")

    # ── Render text ────────────────────────────────────────────────────────────
    t = Text()

    def row(label: str, value: str, vstyle: str = "white"):
        t.append(f"  {label:<20}", style="dim cyan")
        t.append(f": {value}\n", style=vstyle)

    row("Source IP",       ip,        "bold white")
    row("Identity",        identity,  "white")
    if sni_str != "N/A":
        row("TLS SNI / Domain", sni_str, "yellow")
    row("Status",          status,    "bold red" if is_sus else "bold green")
    t.append("\n")
    row("Packet Rate",     f"{feats['rate']:.0f} pkt/s",     "yellow")
    row("SYN Count",       f"{feats['syn_count']:.0f}",      "white")
    row("Unique Ports",    f"{feats['ports_count']:.0f}",    "white")
    row("SYN Ratio",       f"{feats['syn_ratio']:.3f}",      "white")
    row("Port Diversity",  f"{feats['port_diversity']:.3f}", "white")
    row("Payload Entropy", f"{feats['payload_entropy']:.3f}","white")
    t.append("\n")
    heur_str = ", ".join(heuristic_triggered) if heuristic_triggered else "No rule triggered"
    row("Heuristic",  heur_str, "red" if heuristic_triggered else "dim")
    if is_trusted:
        row("LightGBM", f"Bypassed (Trusted: {trusted_reason})", "dim green")
        row("Autoencoder", f"Bypassed (Trusted: {trusted_reason})", "dim green")
    elif not ml_eligible:
        prob_str = f"prob {lgbm_prob:.3f} " if lgbm_prob is not None else ""
        row("LightGBM", f"{prob_str}(Standby — rate < {ML_MIN_RATE} pkt/s)", "dim")
        mse_str = f"MSE {ae_mse:.4f} " if ae_mse is not None else ""
        row("Autoencoder", f"{mse_str}(Standby — rate < {ML_MIN_RATE} pkt/s)", "dim")
        if ae_thresh is not None:
            row("AE Threshold", f"{ae_thresh:.4f}", "dim")
    else:
        if lgbm_prob is not None:
            row("LightGBM", f"prob {lgbm_prob:.3f}" + (" [FLAGGED]" if lgbm_flag else ""),
                "red" if lgbm_flag else "green")
        else:
            row("LightGBM",  "N/A", "dim")
        if ae_mse is not None and ae_thresh is not None:
            row("Autoencoder",
                f"MSE {ae_mse:.4f}" + (" [FLAGGED]" if ae_flag else ""),
                "red" if ae_flag else "green")
            row("AE Threshold", f"{ae_thresh:.4f}", "dim")
        else:
            row("Autoencoder", "N/A", "dim")
    t.append("\n")
    row("Detection Source", detection_source, "bold yellow" if sources else "dim")
    t.append(f"  {'Final Verdict':<20}: ", style="dim cyan")
    t.append_text(Text.from_markup(f"{verdict}\n"))
    t.append("\n")
    t.append("  WHY FLAGGED?\n" if is_sus else "  ASSESSMENT SUMMARY:\n", style="bold cyan")
    for r in reasons:
        style = "green" if r.startswith("✓") else ("yellow" if r.startswith("•") else "dim")
        t.append(f"    {r}\n", style=style)
    t.append("\n")
    t.append("  [ESC] Back     [↑/↓] Navigate     [Q] Quit", style="dim")

    border = "red" if is_sus else "green"
    panel_title = "[bold red]╠══ THREAT DETAILS ══╣[/bold red]" if is_sus else "[bold green]╠══ SESSION DETAILS ══╣[/bold green]"
    return Panel(t, title=panel_title, border_style=border, padding=(0, 1))


# ─── SIMULATION STATUS PANEL ──────────────────────────────────────────────────
def _render_sim_panel() -> Panel:
    """Build the Simulation Status panel from .sim_status.json written by
    packet_simulator.py.  Pure UI display — no detection logic here.
    The actual anomaly detection still runs through the existing IDS pipeline."""
    sim         = _read_sim_status()
    mode_str    = sim.get("mode", "INACTIVE")
    pkts_sent   = sim.get("packets_sent", 0)
    is_active   = (mode_str != "INACTIVE")

    text = Text()
    text.append("SIMULATION STATUS\n", style="bold cyan")

    if is_active:
        text.append("\u25cf ACTIVE\n", style="bold green")
        label = mode_str[:28]
        text.append("Mode     : ", style="dim")
        text.append(f"{label}\n", style="bold yellow")
        text.append("Pkt Sent : ", style="dim")
        text.append(f"{pkts_sent:,}\n", style="cyan")
        text.append("\n")
        text.append("IDS captures via Scapy\n", style="dim")
        text.append("Autoencoder detects anomalies\n", style="dim")
        text.append("\u2192 Watch Alert Status column", style="dim")
    else:
        text.append("\u25cb INACTIVE\n", style="dim")
        text.append("\n")
        text.append("Run packet_simulator.py\n", style="dim")
        text.append("to start a simulation.\n", style="dim")
        text.append("\n")
        text.append("  python packet_simulator.py", style="dim bold")

    border = "green" if is_active else "dim"
    return Panel(text, border_style=border, padding=(0, 1))


# ─── MAIN TABLE (with viewport scrolling) ──────────────────────────────────────
def _build_main_table(display_data: list, selected_idx: int, mode: str, max_rows: int = None) -> Table:
    """Build the main IP table. Highlights the selected row in dashboard mode and supports viewport scrolling."""
    table_width = min(console.width, 165)
    ip_col_width = max(40, table_width - 80)

    total_count = len(display_data)
    if max_rows and total_count > max_rows:
        half = max_rows // 2
        start_idx = max(0, min(selected_idx - half, total_count - max_rows))
        end_idx = start_idx + max_rows
        visible_rows = display_data[start_idx:end_idx]
        title_str = (
            f"[bold cyan]ACTIVE NETWORK SESSIONS[/bold cyan] "
            f"[dim]({total_count} Total | Showing {start_idx + 1}-{end_idx} — use ↑/↓ to scroll)[/dim]"
        )
    else:
        start_idx = 0
        visible_rows = display_data
        title_str = (
            f"[bold cyan]ACTIVE NETWORK SESSIONS[/bold cyan] "
            f"[dim]({total_count} Active)[/dim]"
        )

    table = Table(title=title_str, show_header=True, header_style="bold cyan", width=table_width)
    table.add_column("Source IP / Identity [App/Domain]", width=ip_col_width)
    table.add_column("Rate (pkt/s)", justify="right", width=12)
    table.add_column("Ports", justify="right", width=15)
    table.add_column("Alert Status", style="red", width=45)

    for i, row in enumerate(visible_rows):
        orig_idx = start_idx + i
        # Highlight selected row with reverse style in dashboard mode
        if mode == "dashboard" and orig_idx == selected_idx:
            name_cell  = f"[reverse]{row['name']}[/reverse]"
            rate_cell  = f"[reverse]{row['rate']}[/reverse]"
            ports_cell = f"[reverse]{row['ports']}[/reverse]"
            stat_cell  = f"[reverse]{row['status']}[/reverse]"
        else:
            name_cell  = row['name']
            rate_cell  = str(row['rate'])
            ports_cell = str(row['ports'])
            stat_cell  = row['status']
        table.add_row(name_cell, rate_cell, ports_cell, stat_cell)

    return table


def generate_table():
    """Main render function — returns a Rich renderable.
    In dashboard mode: Top tabs (Traffic, Top IPs, Simulation Status) at top + telemetry + sessions table.
    In detail mode: compact table + full threat detail panel.
    All existing detection logic, window expiry, and telemetry preserved."""
    render_start = time.time()
    check_window_expiration(render_start)

    # ── Append current PPS to rolling history ──────────────────────────────────
    pps_history.append(global_stats['current_pps'])

    macro_alerts = []
    # Count only active IPs transmitting in the current window
    unique_ips_count = sum(1 for ip in tracker if tracker[ip]['display_rate'] > 0 or tracker[ip]['alerts'])
    
    if global_stats['total_packets'] > GLOBAL_DOS_THRESHOLD:
        macro_alerts.append(f"GLOBAL DDoS ({global_stats['total_packets']} pkts/s)")
    if unique_ips_count > SWARM_THRESHOLD:
        macro_alerts.append(f"BOTNET SWARM ({unique_ips_count} active IPs)")
    if global_stats['syn_count'] > GLOBAL_SYN_THRESHOLD:
        macro_alerts.append("GLOBAL TCP SYN FLOOD")
        log_alert("SYN Flood", None, f"Global network TCP SYN flood ({global_stats['syn_count']} SYNs/window)")

    if macro_alerts:
        alert_banner = f"[bold red]  ⚠  MACRO ALERTS: {' | '.join(macro_alerts)}  ⚠ [/bold red]"
    else:
        alert_banner = ""

    # ── Build sorted display_data (unchanged from original) ───────────────────
    display_data = []
    snapshot_ips = list(tracker.keys())
    for ip in snapshot_ips:
        data = tracker[ip]
        if data['display_rate'] > 0 or data['alerts']:
            is_sus    = len(data['alerts']) > 0
            alert_str = ", ".join(data['alerts']) if data['alerts'] else "[green]Normal[/green]"
            display_name = get_ip_identity(ip)
            if data['snis']:
                sni_str = ", ".join(list(data['snis'].copy())[:2])
                display_name = f"{display_name} [yellow]\\[{sni_str}][/yellow]"
            if is_sus:
                display_name = f"[bold red][!] {display_name}[/bold red]"
            else:
                display_name = f"    {display_name}"
            display_data.append({
                'ip_raw': ip, 'name': display_name, 'rate': data['display_rate'],
                'ports': ", ".join(map(str, list(data['ports'].copy())[:3])) if data['ports'] else "None",
                'status': alert_str, 'is_sus': is_sus
            })

    display_data.sort(key=lambda x: get_ip_order(x['ip_raw']))

    # Update shared display list so keyboard thread can read IP order
    with ui_lock:
        ui_state["display_list"] = [r['ip_raw'] for r in display_data]
        sel_idx = ui_state["selected_idx"]
        mode    = ui_state["mode"]
        sel_ip  = ui_state["selected_ip"]
        # If selected IP dropped off, return to dashboard
        if mode == "detail" and sel_ip not in tracker:
            ui_state["mode"]     = "dashboard"
            ui_state["selected_ip"] = None
            mode = "dashboard"

    # ── Telemetry caption (unchanged) ─────────────────────────────────────────
    render_ms = (time.time() - render_start) * 1000
    ml_status = (
        f"[bold green]Active ({ml_detector.status_string})[/bold green]"
        if ml_detector.is_trained
        else f"[yellow]Standby ({ml_detector.status_string})[/yellow]"
    )

    # ── Keyboard hints ────────────────────────────────────────────────────────
    if mode == "dashboard":
        hint = "[dim]↑/↓ select   Enter → details   Q quit[/dim]"
    else:
        hint = "[dim]ESC back   ↑/↓ navigate   Q quit[/dim]"

    telemetry = (
        f"[yellow]Telemetry:[/yellow] UI Render: [cyan]{render_ms:.2f}ms[/cyan]"
        f" | Latency: [cyan]{global_stats['avg_latency_ms']:.3f}ms[/cyan]"
        f" | Throughput: [cyan]{global_stats['current_pps']} pkts/sec[/cyan]"
        f" | ML Status: {ml_status}"
        + (f"\n{alert_banner}" if alert_banner else "")
        + f"\n{hint}"
    )

    from rich.console import Group

    # ── Top-row tabs: Traffic Graph | Top Active IPs ──────────────────────────────
    # Placed at the top so they stay pinned and visible regardless of IP volume
    graph_panel   = _render_graph()
    top_ips_panel = _render_top_ips()
    top_row       = Columns([graph_panel, top_ips_panel], equal=True, expand=True)

    header_banner    = Text("REAL-TIME THREAT DASHBOARD V5 — OFFLINE DPI & TELEMETRY", style="bold cyan", justify="center")
    telemetry_banner = Text.from_markup(telemetry)

    if mode == "detail":
        # ── Detail view: header + compact table + full threat detail panel ────
        detail_ip = sel_ip if (sel_ip and sel_ip in tracker) else None
        if detail_ip:
            detail = _render_detail_panel(detail_ip)
        else:
            detail = Panel("[yellow]Selected IP is no longer active.[/yellow]\n[dim][ESC] Back[/dim]",
                           border_style="dim")
        main_table = _build_main_table(display_data, sel_idx, mode, max_rows=3)
        return Group(header_banner, main_table, detail)
    else:
        # ── Dashboard view: Header → Top 3 Tabs → Telemetry → Active Sessions Table ──
        term_height = console.height or 30
        avail_rows = max(5, term_height - 17)
        main_table = _build_main_table(display_data, sel_idx, mode, max_rows=avail_rows)
        return Group(header_banner, top_row, telemetry_banner, main_table)


def process_packet(packet):
    global start_time, tracker, global_stats
    current_time = time.time()
    
    latency_ms = (current_time - float(packet.time)) * 1000
    global_stats['total_latency_ms'] += latency_ms
    global_stats['packets_this_second'] += 1
    
    check_window_expiration(current_time) 
        
    if IP in packet or IPv6 in packet:
        src_ip = packet[IP].src if IP in packet else packet[IPv6].src
        dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst
        
        tracker[src_ip]['total_packets'] += 1
        tracker[src_ip]['last_seen'] = current_time
        global_stats['total_packets'] += 1
        
        if packet.haslayer(TLS_Ext_ServerName):
            try:
                snis = packet[TLS_Ext_ServerName].servernames
                if snis:
                    sni_name = snis[0].servername.decode('utf-8')
                    tracker[dst_ip]['snis'].add(sni_name)
            except Exception:
                pass
        
        # --- DPI & Threat Analysis ---
        
        # 1. DEFINE TRUSTED STATUS FIRST
        identity = get_ip_identity(src_ip)
        is_trusted = any(org in identity for org in TRUSTED_ORGS)
        
        if not is_trusted and dst_ip in tracker:
            for sni in tracker[dst_ip]['snis']:
                if any(domain in sni for domain in TRUSTED_DOMAINS):
                    is_trusted = True
                    break

        # 2. TRANSPORT LAYER PARSING
        if TCP in packet:
            tracker[src_ip]['ports'].add(packet[TCP].dport)
            flags = packet[TCP].flags
            
            if src_ip == dst_ip and "LAND Attack" not in tracker[src_ip]['alerts']:
                tracker[src_ip]['alerts'].append("LAND Attack")
                log_alert("LAND Attack", src_ip, "Spoofed loopback (Source IP equals Destination IP)")
            if flags & 0x29 == 0x29 and "XMAS Scan" not in tracker[src_ip]['alerts']:
                tracker[src_ip]['alerts'].append("XMAS Scan")
                log_alert("XMAS Scan", src_ip, "Stealth probe with FIN+PSH+URG flags (0x29)")
            if int(flags) == 0 and "NULL Scan" not in tracker[src_ip]['alerts']:
                tracker[src_ip]['alerts'].append("NULL Scan")
                log_alert("NULL Scan", src_ip, "Stealth probe with zero TCP flags set (0x00)")
            if 'S' in flags:
                tracker[src_ip]['syn_count'] += 1
                global_stats['syn_count'] += 1
                if tracker[src_ip]['syn_count'] > INDIVIDUAL_SYN_THRESHOLD and "SYN Flood" not in tracker[src_ip]['alerts']:
                    tracker[src_ip]['alerts'].append("SYN Flood")
                    log_alert("SYN Flood", src_ip, f"Exceeded threshold with {tracker[src_ip]['syn_count']} TCP SYN requests")

        elif UDP in packet:
            tracker[src_ip]['ports'].add(packet[UDP].dport)

        # ---> MOVED RAW PAYLOAD EXTRACTION HERE <---
        if Raw in packet:
            tracker[src_ip]['payload_sizes'][len(packet[Raw].load)] += 1

        # 3. FEATURE EXTRACTION & ML PREDICTION
        rate = tracker[src_ip]['total_packets']
        ports_count = len(tracker[src_ip]['ports'])
        syn_count = tracker[src_ip]['syn_count']
        unique_payloads = tracker[src_ip]['payload_sizes'] # Now contains the latest packet data!

        if not is_trusted:
            features = ml_detector.extract_features(rate, ports_count, syn_count, unique_payloads)
            
            if ml_detector.is_trained:
                # Only run ML when rate is meaningful AND at a reduced frequency.
                # rate < ML_MIN_RATE = low-volume local traffic (router, mDNS, etc.) — skip.
                # rate % ML_CHECK_INTERVAL throttles how often we run the model per IP.
                if rate >= ML_MIN_RATE and rate % ML_CHECK_INTERVAL == 0:
                    is_anomaly = ml_detector.predict(features)
                    if is_anomaly and "ML Anomaly" not in tracker[src_ip]['alerts']:
                        tracker[src_ip]['alerts'].append("ML Anomaly")
                        log_alert("ML Anomaly", src_ip, f"Ensemble deviation | Rate: {rate} pkts/s, Ports: {ports_count}")
            else:
                ml_detector.observe(features)

        # 4. STATIC HEURISTIC CHECKS
        if len(tracker[src_ip]['ports']) >= PORT_SCAN_THRESHOLD and "Port Scan" not in tracker[src_ip]['alerts']:
            tracker[src_ip]['alerts'].append("Port Scan")
            log_alert("Port Scan", src_ip, f"Scanned {len(tracker[src_ip]['ports'])} unique ports: {list(tracker[src_ip]['ports'])[:5]}...")

        if rate > DOS_THRESHOLD and not is_trusted and "Volumetric DoS" not in tracker[src_ip]['alerts']:
            tracker[src_ip]['alerts'].append("Volumetric DoS")
            log_alert("Volumetric DoS", src_ip, f"Packet flood of {rate} pkts/s (Threshold: {DOS_THRESHOLD})")
            
        if rate > BOT_RATE_THRESHOLD and len(tracker[src_ip]['payload_sizes']) == 1 and not is_trusted and "Automated Bot" not in tracker[src_ip]['alerts']:
            tracker[src_ip]['alerts'].append("Automated Bot")
            log_alert("Automated Bot", src_ip, f"Rate {rate} pkts/s with static uniform payload size")


# ─── KEYBOARD INPUT THREAD ─────────────────────────────────────────────────────
def _keyboard_thread():
    """Non-blocking keyboard reader using msvcrt on Windows.
    Runs in a daemon thread — never blocks the sniffer or UI loops."""
    try:
        import msvcrt
    except ImportError:
        return   # Non-Windows: keyboard navigation not available

    while True:
        try:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                with ui_lock:
                    mode      = ui_state["mode"]
                    disp_list = ui_state["display_list"]
                    idx       = ui_state["selected_idx"]
                    n         = len(disp_list)

                    if ch == '\x1b':           # ESC
                        ui_state["mode"]        = "dashboard"
                        ui_state["selected_ip"] = None
                    elif ch in ('q', 'Q'):
                        import os; os._exit(0)
                    elif ch == '\r':           # Enter
                        if mode == "dashboard" and n > 0:
                            sel = disp_list[min(idx, n - 1)]
                            ui_state["mode"]        = "detail"
                            ui_state["selected_ip"] = sel
                    elif ch == '\xe0':         # Arrow key prefix on Windows
                        arrow = msvcrt.getwch()
                        if arrow == 'H':       # Up
                            ui_state["selected_idx"] = max(0, idx - 1)
                        elif arrow == 'P':     # Down
                            ui_state["selected_idx"] = min(max(n - 1, 0), idx + 1)
            time.sleep(0.05)
        except Exception:
            time.sleep(0.1)


if __name__ == "__main__":
    import threading

    active_iface = get_best_iface()
    iface_desc = getattr(IFACES.get(active_iface, None), 'description', active_iface)

    # Print startup messages BEFORE entering the alternate screen buffer,
    # so the user can read them even after Live takes over the display.
    console.print("[bold green][*] Initializing Network Anomaly Detector V5...[/bold green]")
    console.print(f"[bold cyan][*] Sniffing on: {iface_desc}[/bold cyan]")
    console.print("[dim]Controls: ↑/↓ select IP | Enter = Threat Details | ESC = Back | Q = Quit[/dim]")

    sniffer_thread = threading.Thread(
        target=lambda: sniff(iface=active_iface, prn=process_packet, store=False),
        daemon=True
    )
    sniffer_thread.start()

    kb_thread = threading.Thread(target=_keyboard_thread, daemon=True)
    kb_thread.start()

    try:
        # screen=True uses the alternate terminal buffer (like htop/vim).
        # This eliminates the repeated-header glitch caused by Rich miscounting
        # how many lines to scroll back on Windows PowerShell / cmd.
        with Live(
            generate_table(),
            refresh_per_second=2,
            console=console,
            screen=True,          # ← key fix: alternate screen buffer
        ) as live:
            while True:
                time.sleep(0.5)
                live.update(generate_table())
    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] Monitoring stopped by user.[/bold yellow]")