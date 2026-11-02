import subprocess
import time
import os
from rich.console import Console
from rich.table import Table

console = Console()
LOG_FILE = "alerts.log"

def clear_log():
    """Wipes the log file clean before each test."""
    with open(LOG_FILE, "w") as f:
        f.write("")

def run_test(script_name, expected_alerts, duration=25):
    """Runs an attack script for `duration` seconds and reads the resulting logs.

    Timeline per test:
      - clear_log()   : wipe log so previous test results don't bleed in
      - STARTUP_GRACE : let the attack script fully initialise
      - duration      : active attack window (covers multiple detector TIME_WINDOWs)
      - FLUSH_WAIT    : after killing the attack, give detector time to write final alerts
    """
    STARTUP_GRACE = 2   # seconds for subprocess to spin up and start sending
    FLUSH_WAIT    = 6   # seconds after kill — covers one full detector TIME_WINDOW (5s)

    # Wipe log NOW (not before — give previous test's flush wait time to finish)
    console.print(f"\n[cyan][*] Launching {script_name}...[/cyan]")
    clear_log()

    try:
        process = subprocess.Popen(
            ["python", script_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE          # capture stderr to catch silent crashes
        )
        # Give a moment then check if it already crashed
        time.sleep(0.5)
        if process.poll() is not None:      # process died immediately
            err = process.stderr.read().decode(errors='replace').strip()
            console.print(f"  [bold red][!] {script_name} crashed on startup:[/bold red]")
            console.print(f"  [red]{err[-300:]}[/red]")   # show last 300 chars of error
            return []

        # Grace period: wait for the script to fully start before the timer
        time.sleep(STARTUP_GRACE)

        # Active window with visible countdown
        console.print(f"  [dim]Running for {duration}s …[/dim]")
        for remaining in range(duration, 0, -5):
            time.sleep(min(5, remaining))
            left = max(0, remaining - 5)
            console.print(f"  [dim]  ↳ {left}s remaining …[/dim]")
        console.print("  [dim]  ↳ done.[/dim]")

        # Kill the attack
        process.terminate()
        process.wait()

        # ── FLUSH WAIT ───────────────────────────────────────────────────────
        # Detector processes packets asynchronously. After the attack stops,
        # the current TIME_WINDOW may not have elapsed yet — wait one full window
        # so detector finishes evaluating and writes all alerts to the log.
        console.print(f"  [yellow]  ↳ Waiting {FLUSH_WAIT}s for detector to flush alerts…[/yellow]")
        time.sleep(FLUSH_WAIT)

    except FileNotFoundError:
        console.print(f"[bold red][!] Could not find {script_name}[/bold red]")
        return []

    # Parse the detector's log file
    detected = set()
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            content = f.read().strip()

        # Show raw log contents for transparency
        if content:
            console.print(f"  [dim]Log: {content.replace(chr(10), ', ')}[/dim]")
        else:
            console.print("  [bold red]  ↳ alerts.log is empty — no alerts fired![/bold red]")

        for alert in expected_alerts:
            if alert in content:
                detected.add(alert)

    return list(detected)


if __name__ == "__main__":
    console.clear()
    console.print("[bold green]=== IDS AUTOMATED TEST SUITE ===[/bold green]")
    console.print("[yellow]Note: Ensure detector.py is running in a separate terminal before starting![/yellow]")
    
    # Define the test suite
    tests = [
        {"script": "scanner.py", "expected": ["Port Scan", "Automated Bot"]},
        {"script": "attack.py", "expected": ["Volumetric DoS"]},
        {"script": "advanced_attack.py", "expected": ["LAND Attack", "XMAS Scan", "NULL Scan"]},
        {"script": "syn_flood.py", "expected": ["SYN Flood"]} 
    ]
    
    results = []
    
    # Execute the tests sequentially
    for test in tests:
        detected = run_test(test["script"], test["expected"])
        
        # Calculate success (Did we catch everything we expected to catch?)
        success = len(detected) == len(test["expected"])
        
        results.append({
            "script": test["script"],
            "expected": test["expected"],
            "detected": detected,
            "status": "[bold green]PASS[/bold green]" if success else "[bold red]FAIL[/bold red]"
        })
        
    # Print the final report card
    console.print("\n")
    table = Table(title="Test Results Summary", show_header=True, header_style="bold cyan")
    table.add_column("Attack Script", width=20)
    table.add_column("Expected Alerts", width=35)
    table.add_column("Detected Alerts", width=35)
    table.add_column("Status", width=10)
    
    for r in results:
        expected_str = ", ".join(r["expected"])
        detected_str = ", ".join(r["detected"]) if r["detected"] else "None"
        table.add_row(r["script"], expected_str, detected_str, r["status"])
        
    console.print(table)