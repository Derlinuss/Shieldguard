import os
import shutil
import json
import time
import threading
from datetime import datetime
from scanner import Scanner, FolderMonitor
from algorithm import (
    full_analysis, quick_scan_file, update_database_from_web,
    web_search_unknown_file, add_whitelist, load_database, hash_lookup,
)

QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shieldguard.log")


class QuarantineManager:
    def __init__(self, quarantine_path=QUARANTINE_DIR):
        self.path = quarantine_path
        os.makedirs(self.path, exist_ok=True)
        self._index_path = os.path.join(self.path, "index.json")
        self._index = self._load_index()

    def _load_index(self):
        if os.path.exists(self._index_path):
            try:
                with open(self._index_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"entries": []}

    def _save_index(self):
        with open(self._index_path, "w") as f:
            json.dump(self._index, f, indent=2, default=str)

    def quarantine(self, filepath):
        if not os.path.isfile(filepath):
            return False, "File not found"
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            fname = os.path.basename(filepath)
            dest = os.path.join(self.path, f"{timestamp}_{fname}")

            # Move to quarantine with metadata
            shutil.move(filepath, dest)
            entry = {
                "original_path": os.path.abspath(filepath),
                "quarantined_path": dest,
                "timestamp": datetime.now().isoformat(),
                "size": os.path.getsize(dest),
                "restored": False,
            }

            # Capture threat info
            analysis = full_analysis(dest)
            entry["threats"] = [t for t in analysis["threats"]]
            entry["heuristic"] = analysis["heuristic"]

            self._index["entries"].append(entry)
            self._save_index()
            log_action(f"QUARANTINED: {filepath} -> {dest}")
            return True, dest
        except (IOError, PermissionError, OSError) as e:
            return False, str(e)

    def restore(self, quarantined_path):
        for entry in self._index["entries"]:
            if entry["quarantined_path"] == quarantined_path and not entry["restored"]:
                try:
                    dest = entry["original_path"]
                    shutil.move(quarantined_path, dest)
                    entry["restored"] = True
                    entry["restored_at"] = datetime.now().isoformat()
                    self._save_index()
                    log_action(f"RESTORED: {quarantined_path} -> {dest}")
                    return True, dest
                except (IOError, OSError) as e:
                    return False, str(e)
        return False, "Entry not found or already restored"

    def delete_permanently(self, quarantined_path):
        for i, entry in enumerate(self._index["entries"]):
            if entry["quarantined_path"] == quarantined_path:
                try:
                    if os.path.isfile(quarantined_path):
                        os.remove(quarantined_path)
                    self._index["entries"].pop(i)
                    self._save_index()
                    log_action(f"DELETED: {quarantined_path}")
                    return True, "Deleted permanently"
                except (IOError, OSError) as e:
                    return False, str(e)
        return False, "Entry not found"

    def list_quarantined(self):
        return self._index["entries"]

    def clear_restored(self):
        self._index["entries"] = [e for e in self._index["entries"] if not e.get("restored")]
        self._save_index()


class AntiVirus:
    def __init__(self):
        self.scanner = Scanner()
        self.quarantine = QuarantineManager()
        self.monitor = None
        self._running = False

    def quick_scan(self, path, callback=None):
        log_action(f"STARTED QUICK SCAN: {path}")
        results = []
        if os.path.isfile(path):
            r = self.scanner.scan_file(path, callback)
            if r:
                results.append(r)
        else:
            results = self.scanner.scan_directory(path, callback)
        log_action(f"FINISHED QUICK SCAN: {len(results)} threats found")
        return results

    def full_scan(self, path, callback=None):
        """Full scan uses deep analysis with heuristics enabled"""
        log_action(f"STARTED FULL SCAN: {path}")
        self.scanner._stop.clear()
        self.scanner._paused.set()
        self.scanner.stats = {"scanned": 0, "infected": 0, "errors": 0, "whitelisted": 0}
        self.scanner.results = []

        if os.path.isfile(path):
            r = full_analysis(path)
            if callback:
                callback(r)
            return [r] if r["detected"] else []
        else:
            results = self.scanner.scan_directory(path, callback)
            log_action(f"FINISHED FULL SCAN: {len(results)} threats found")
            return results

    def scan_and_quarantine(self, path, callback=None):
        results = self.full_scan(path, callback)
        for r in results:
            if r["detected"]:
                success, msg = self.quarantine.quarantine(r["filepath"])
                if success:
                    yield r["filepath"], "quarantined", msg
                else:
                    yield r["filepath"], "failed", msg

    def start_realtime_protection(self, paths=None, callback=None):
        if self._running:
            return
        self._running = True
        self.monitor = FolderMonitor(
            paths=paths or [os.path.expanduser("~\\Downloads"), os.path.expanduser("~\\Desktop")],
            callback=lambda fpath: self._on_new_file(fpath, callback),
        )
        self.monitor.start()
        log_action("REALTIME PROTECTION STARTED")
        return True

    def stop_realtime_protection(self):
        self._running = False
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
            log_action("REALTIME PROTECTION STOPPED")
        return True

    def _on_new_file(self, fpath, callback=None):
        ext = os.path.splitext(fpath)[1].lower()
        if ext not in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".zip", ".rar"}:
            return
        result = quick_scan_file(fpath)
        if result and result[0].get("detected"):
            self.quarantine.quarantine(fpath)
            if callback:
                callback("blocked", fpath)
        elif callback:
            callback("allowed", fpath)

    def update_virus_definitions(self):
        success, msg = update_database_from_web()
        log_action(f"UPDATE: {msg}")
        return success, msg

    def lookup_online(self, filepath):
        result = web_search_unknown_file(filepath)
        log_action(f"ONLINE LOOKUP: {filepath} -> {result}")
        return result

    def whitelist_file(self, filepath):
        add_whitelist(filepath)
        log_action(f"WHITELISTED: {filepath}")

    def get_stats(self):
        return dict(self.scanner.stats)

    def generate_report(self, scan_results=None):
        os.makedirs(REPORT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = {
            "timestamp": datetime.now().isoformat(),
            "threats_found": len(scan_results or []),
            "details": scan_results or [],
            "scan_stats": self.scanner.stats,
        }
        path = os.path.join(REPORT_DIR, f"report_{timestamp}.json")
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        return path


def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")
    except IOError:
        pass
    return entry
