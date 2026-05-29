import sys
import os
import time
import threading
import json

from antivirus import AntiVirus, LOG_FILE, REPORT_DIR
from ui import (
    banner, menu, quarantine_menu, protection_menu, clear_screen,
    get_input, print_separator, result_summary, print_quarantine_entry,
    print_report_summary, error_text, success_text, info_text, warning_text,
    threat_line, Colors as C,
)

try:
    from gui import ShieldGuardGUI
    HAVE_GUI = True
except ImportError:
    HAVE_GUI = False


class ShieldGuardApp:
    def __init__(self):
        self.av = AntiVirus()
        self._scan_thread = None
        self._realtime_active = False

    def run(self):
        while True:
            clear_screen()
            banner()
            menu()
            choice = get_input("Select an option: ")

            if choice == "1":
                self._quick_scan()
            elif choice == "2":
                self._full_scan()
            elif choice == "3":
                self._scan_and_quarantine()
            elif choice == "4":
                self._quarantine_manager()
            elif choice == "5":
                self._realtime_protection()
            elif choice == "6":
                self._update_defs()
            elif choice == "7":
                self._online_lookup()
            elif choice == "8":
                self._view_report()
            elif choice == "9":
                self._view_log()
            elif choice.lower() == "g":
                self._launch_gui()
            elif choice == "0":
                print(f"\n{C.CYAN}Shutting down ShieldGuard...{C.RESET}")
                if self._realtime_active:
                    self.av.stop_realtime_protection()
                print(f"{C.GREEN}Goodbye.{C.RESET}")
                break
            else:
                error_text("Invalid option")

            if choice not in ("0",):
                input(f"\n  {C.DIM}Press Enter to continue...{C.RESET}")

    def _callback(self, result):
        if result and result.get("detected"):
            for t in result.get("threats", []):
                print(f"  {C.RED}\u26a0 {t.get('name', 'Threat')} -> {os.path.basename(result['filepath'])}{C.RESET}")

    def _quick_scan(self):
        clear_screen()
        banner()
        info_text("Quick Scan: Scanning Downloads folder...")
        start = time.time()
        self.av.quick_scan(os.path.expanduser("~/Downloads"), callback=self._callback)
        elapsed = time.time() - start
        result_summary(self.av.get_stats(), elapsed)

    def _full_scan(self):
        clear_screen()
        banner()
        custom = get_input("Enter path to scan (or press Enter for /): ") or "/"
        if not os.path.exists(custom):
            error_text("Path does not exist")
            return
        info_text(f"Full Scan in progress: {custom}")
        start = time.time()
        self.av.full_scan(custom, callback=self._callback)
        elapsed = time.time() - start
        result_summary(self.av.get_stats(), elapsed)

    def _scan_and_quarantine(self):
        clear_screen()
        banner()
        path = get_input("Enter path to scan: ") or os.path.expanduser("~/Downloads")
        if not os.path.exists(path):
            error_text("Path does not exist")
            return
        info_text(f"Scanning & quarantining threats in: {path}")
        count = 0
        for fpath, action, msg in self.av.scan_and_quarantine(path):
            if action == "quarantined":
                success_text(f"Quarantined: {os.path.basename(fpath)}")
            else:
                error_text(f"Failed: {os.path.basename(fpath)} - {msg}")
            count += 1
        if count == 0:
            success_text("No threats found")
        print()

    def _quarantine_manager(self):
        q = self.av.quarantine
        while True:
            clear_screen()
            banner()
            quarantine_menu()
            choice = get_input("Select: ")
            if choice == "1":
                entries = q.list_quarantined()
                if not entries:
                    info_text("Quarantine is empty")
                else:
                    print()
                    for i, e in enumerate(entries, 1):
                        print_quarantine_entry(e, i)
                        print()
            elif choice == "2":
                path = get_input("Full path of quarantined item: ")
                success, msg = q.restore(path)
                if success:
                    success_text(f"Restored to: {msg}")
                else:
                    error_text(msg)
            elif choice == "3":
                path = get_input("Full path of quarantined item: ")
                confirm = get_input("Delete permanently? (y/N): ").lower()
                if confirm == "y":
                    success, msg = q.delete_permanently(path)
                    if success:
                        success_text(msg)
                    else:
                        error_text(msg)
            elif choice == "4":
                break
            if choice != "4":
                input(f"\n  {C.DIM}Press Enter...{C.RESET}")

    def _realtime_protection(self):
        while True:
            clear_screen()
            banner()
            status = f"{C.GREEN}ACTIVE{C.RESET}" if self._realtime_active else f"{C.RED}INACTIVE{C.RESET}"
            info_text(f"Real-Time Protection: {status}")
            protection_menu()
            choice = get_input("Select: ")
            if choice == "1":
                if self._realtime_active:
                    warning_text("Already active")
                else:
                    self.av.start_realtime_protection(
                        callback=lambda action, fpath: success_text(f"{action.upper()}: {os.path.basename(fpath)}")
                    )
                    self._realtime_active = True
                    success_text("Monitoring started (Desktop & Downloads)")
            elif choice == "2":
                if self._realtime_active:
                    self.av.stop_realtime_protection()
                    self._realtime_active = False
                    success_text("Monitoring stopped")
                else:
                    warning_text("Not active")
            elif choice == "3":
                break
            if choice != "3":
                input(f"\n  {C.DIM}Press Enter...{C.RESET}")

    def _update_defs(self):
        info_text("Checking for virus definition updates...")
        success, msg = self.av.update_virus_definitions()
        if success:
            success_text(msg)
        else:
            warning_text(f"Update failed: {msg}")
            info_text("Using built-in definitions")

    def _online_lookup(self):
        path = get_input("Enter file path for online lookup: ")
        if not os.path.isfile(path):
            error_text("File not found")
            return
        info_text("Looking up file hash online...")
        result = self.av.lookup_online(path)
        print()
        if result.get("detected"):
            print(f"  {C.RED}{C.BOLD}\u26a0  THREAT DETECTED BY {result.get('source', 'online')}{C.RESET}")
            print(f"     Malicious: {result.get('malicious', 0)} engines")
            print(f"     Suspicious: {result.get('suspicious', 0)} engines")
        else:
            print(f"  {C.GREEN}\u2713  File appears clean ({result.get('source', 'online')}){C.RESET}")
            if result.get("error"):
                print(f"     Note: {result['error']}")

    def _view_report(self):
        if not os.path.isdir(REPORT_DIR):
            info_text("No reports found")
            return
        reports = sorted(
            [f for f in os.listdir(REPORT_DIR) if f.endswith(".json")],
            reverse=True,
        )
        if not reports:
            info_text("No reports found")
            return
        print(f"\n{C.CYAN}Recent Reports:{C.RESET}")
        for i, r in enumerate(reports[:10], 1):
            print(f"  {i}. {r}")
        choice = get_input("Report number (or 0 to cancel): ")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(reports):
                with open(os.path.join(REPORT_DIR, reports[idx])) as f:
                    data = json.load(f)
                print_report_summary(reports[idx], data)
        except (ValueError, IndexError, json.JSONDecodeError):
            pass

    def _view_log(self):
        if not os.path.isfile(LOG_FILE):
            info_text("No log entries")
            return
        with open(LOG_FILE) as f:
            lines = f.readlines()
        if not lines:
            info_text("Log is empty")
            return
        print(f"\n{C.CYAN}Last 50 log entries:{C.RESET}")
        print_separator()
        for line in lines[-50:]:
            print(f"  {line.strip()}")

    def _launch_gui(self):
        if not HAVE_GUI:
            error_text("GUI not available (tkinter not installed)")
            return
        info_text("Opening GUI window... (terminal will be blocked until GUI closes)")
        try:
            gui = ShieldGuardGUI()
            gui.run()
        except Exception as e:
            error_text(f"GUI error: {e}")
        clear_screen()
        banner()


def main():
    try:
        app = ShieldGuardApp()
        app.run()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Interrupted. Exiting.{C.RESET}")
    except Exception as e:
        print(f"\n{C.RED}Fatal error: {e}{C.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
