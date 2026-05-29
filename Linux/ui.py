import os
import sys
import threading
from datetime import datetime

try:
    from colorama import init, Fore, Style, Back
    init()
    HAVE_COLORAMA = True
except ImportError:
    HAVE_COLORAMA = False


class Colors:
    if HAVE_COLORAMA:
        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        CYAN = Fore.CYAN
        MAGENTA = Fore.MAGENTA
        WHITE = Fore.WHITE
        BOLD = Style.BRIGHT
        DIM = Style.DIM
        RESET = Style.RESET_ALL
    else:
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        CYAN = "\033[96m"
        MAGENTA = "\033[95m"
        WHITE = "\033[97m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RESET = "\033[0m"

C = Colors


def clear_screen():
    os.system("clear")


def banner():
    print(f"{C.MAGENTA}{C.BOLD}")
    print("  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557")
    print("  \u2551        SHIELDGUARD ANTIVIRUS         \u2551")
    print("  \u2551           v1.0  |  Real-Time         \u2551")
    print("  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d")
    print(f"{C.RESET}")
    print(f"{C.DIM}Scan Engine Ready | {len(threading.enumerate())} threads{C.RESET}")
    print()


def print_separator(char="\u2500", length=50):
    print(f"{C.DIM}{char * length}{C.RESET}")


def threat_line(threat, index=0):
    sev_colors = {
        "critical": f"{C.RED}{C.BOLD}",
        "high": f"{C.RED}",
        "medium": f"{C.YELLOW}",
        "low": f"{C.YELLOW}{C.DIM}",
        "info": f"{C.CYAN}",
    }
    color = sev_colors.get(threat.get("severity", "low"), "")
    severity = threat.get("severity", "?").upper()
    method = threat.get("method", "?").upper()
    name = threat.get("name", threat.get("type", "Unknown"))
    return f"  [{color}{severity}{C.RESET}] {method:>8} | {name}"


def print_threat(threat):
    sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
    color_map = {"critical": C.RED + C.BOLD, "high": C.RED, "medium": C.YELLOW, "low": C.YELLOW + C.DIM}
    sev = threat.get("severity", "low")
    color = color_map.get(sev, C.WHITE)
    label = sev_map.get(sev, "UNKNOWN")
    print(f"  {color}[{label}]{C.RESET} {threat.get('name', threat.get('type', 'Unknown'))}")
    print(f"         Method: {threat.get('method', '?').upper()}")
    print(f"         File: {os.path.basename(threat.get('filepath', '?'))[:60]}")


def result_summary(stats, elapsed=0.0):
    print(f"\n{C.CYAN}{C.BOLD}\u2550\u2550\u2550 SCAN COMPLETE \u2550\u2550\u2550{C.RESET}")
    print(f"  {C.GREEN}Scanned:     {stats.get('scanned', 0)}{C.RESET}")
    print(f"  {C.RED}Infected:    {stats.get('infected', 0)}{C.RESET}")
    print(f"  {C.YELLOW}Whitelisted: {stats.get('whitelisted', 0)}{C.RESET}")
    print(f"  {C.MAGENTA}Errors:     {stats.get('errors', 0)}{C.RESET}")
    if elapsed:
        print(f"  Time:  {elapsed:.1f}s")
    print()


def progress_bar(current, total, width=30):
    if total == 0:
        return
    ratio = current / total
    filled = int(ratio * width)
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    pct = int(ratio * 100)
    print(f"  [{bar}] {pct}%  ({current}/{total})", end="\r")


def menu():
    print(f"\n{C.CYAN}{C.BOLD}MAIN MENU{C.RESET}")
    print_separator()
    print(f"  {C.GREEN}1{C.RESET}  Quick Scan (Downloads)")
    print(f"  {C.GREEN}2{C.RESET}  Full Scan (Custom Path)")
    print(f"  {C.GREEN}3{C.RESET}  Scan & Quarantine")
    print(f"  {C.GREEN}4{C.RESET}  Quarantine Manager")
    print(f"  {C.GREEN}5{C.RESET}  Real-Time Protection")
    print(f"  {C.GREEN}6{C.RESET}  Update Virus Definitions")
    print(f"  {C.GREEN}7{C.RESET}  Online Hash Lookup")
    print(f"  {C.GREEN}8{C.RESET}  View Report")
    print(f"  {C.GREEN}9{C.RESET}  View Log")
    print(f"  {C.MAGENTA}{C.BOLD}G{C.RESET}  GUI Mode (Graphical Window)")
    print(f"  {C.GREEN}0{C.RESET}  Exit")
    print_separator()


def quarantine_menu():
    print(f"\n{C.CYAN}{C.BOLD}QUARANTINE MANAGER{C.RESET}")
    print_separator()
    print(f"  {C.GREEN}1{C.RESET}  List Quarantined Items")
    print(f"  {C.GREEN}2{C.RESET}  Restore Item")
    print(f"  {C.GREEN}3{C.RESET}  Delete Item Permanently")
    print(f"  {C.GREEN}4{C.RESET}  Back to Main Menu")
    print_separator()


def protection_menu():
    print(f"\n{C.CYAN}{C.BOLD}REAL-TIME PROTECTION{C.RESET}")
    print_separator()
    print(f"  {C.GREEN}1{C.RESET}  Start Monitoring (Desktop, Downloads)")
    print(f"  {C.GREEN}2{C.RESET}  Stop Monitoring")
    print(f"  {C.GREEN}3{C.RESET}  Back to Main Menu")
    print_separator()


def error_text(msg):
    print(f"{C.RED}[ERROR] {msg}{C.RESET}")


def success_text(msg):
    print(f"{C.GREEN}[OK] {msg}{C.RESET}")


def info_text(msg):
    print(f"{C.CYAN}[i] {msg}{C.RESET}")


def warning_text(msg):
    print(f"{C.YELLOW}[!] {msg}{C.RESET}")


def get_input(prompt_text):
    try:
        return input(f"  {C.BOLD}{prompt_text}{C.RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        return "0"


def print_quarantine_entry(entry, idx):
    status = f"{C.GREEN}RESTORED{C.RESET}" if entry.get("restored") else f"{C.RED}QUARANTINED{C.RESET}"
    print(f"  {idx}. {status} | {os.path.basename(entry['quarantined_path'])}")
    print(f"     Original: {entry['original_path']}")
    print(f"     Date: {entry.get('timestamp', '?')[:19]}")


def print_report_summary(report_path, data):
    print(f"\n{C.CYAN}{C.BOLD}REPORT SUMMARY{C.RESET}")
    print_separator()
    print(f"  Report:    {os.path.basename(report_path)}")
    print(f"  Date:      {data.get('timestamp', '?')[:19]}")
    print(f"  Threats:   {data.get('threats_found', 0)}")
    for detail in data.get("details", []):
        for t in detail.get("threats", []):
            print_threat(t)
