import os
import threading
import time
import fnmatch
from concurrent.futures import ThreadPoolExecutor, as_completed
from algorithm import (
    full_analysis, quick_scan_file, is_whitelisted,
    hash_lookup, heuristic_scan, load_database,
)

SCAN_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".com", ".pif", ".ocx", ".cpl",
    ".drv", ".msi", ".msp", ".py", ".pl", ".php", ".asp", ".aspx", ".jar",
    ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm",
}
MAX_WORKERS = os.cpu_count() or 4
SCAN_CHUNK_SIZE = 50 * 1024 * 1024  # 50MB chunks for large files


class Scanner:
    def __init__(self):
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._paused.set()
        self.stats = {"scanned": 0, "infected": 0, "errors": 0, "whitelisted": 0}
        self.results = []
        self._lock = threading.Lock()

    def stop(self):
        self._stop.set()

    def pause(self):
        self._paused.clear()

    def resume(self):
        self._paused.set()

    @property
    def is_paused(self):
        return not self._paused.is_set()

    @property
    def is_running(self):
        return not self._stop.is_set() and self.stats["scanned"] > 0

    def _should_scan(self, filepath):
        if self._stop.is_set():
            return False
        ext = os.path.splitext(filepath)[1].lower()
        return ext in SCAN_EXTENSIONS

    def _scan_file(self, filepath):
        if self._stop.is_set():
            return None
        self._paused.wait()

        if is_whitelisted(filepath):
            with self._lock:
                self.stats["whitelisted"] += 1
            return None

        try:
            result = full_analysis(filepath)
            with self._lock:
                self.stats["scanned"] += 1
                if result["detected"]:
                    self.stats["infected"] += 1
                    self.results.append(result)
            return result
        except Exception:
            with self._lock:
                self.stats["errors"] += 1
            return None

    def scan_file(self, filepath, callback=None):
        if not os.path.isfile(filepath):
            return None
        result = self._scan_file(filepath)
        if callback:
            callback(result)
        return result

    def scan_directory(self, path, callback=None):
        self._stop.clear()
        self._paused.set()
        self.stats = {"scanned": 0, "infected": 0, "errors": 0, "whitelisted": 0}
        self.results = []

        if not os.path.isdir(path):
            return self.results

        futures = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for root, dirs, files in os.walk(path):
                if self._stop.is_set():
                    break
                # Skip hidden and system directories (Windows)
                dirs[:] = [d for d in dirs if not d.startswith("$")]
                for fname in files:
                    if self._stop.is_set():
                        break
                    fpath = os.path.join(root, fname)
                    if self._should_scan(fpath):
                        future = executor.submit(self._scan_file, fpath)
                        futures.append(future)

            for future in as_completed(futures):
                if self._stop.is_set():
                    break
                result = future.result()
                if callback:
                    callback(result)

        return self.results


class FolderMonitor(threading.Thread):
    def __init__(self, paths=None, callback=None, interval=2.0):
        super().__init__(daemon=True)
        self.paths = paths or []
        self.callback = callback
        self.interval = interval
        self._stop = threading.Event()
        self._known = {}  # path -> mtime

    def add_path(self, path):
        if path not in self.paths:
            self.paths.append(path)

    def remove_path(self, path):
        if path in self.paths:
            self.paths.remove(path)

    def stop(self):
        self._stop.set()

    def run(self):
        while not self._stop.is_set():
            for path in self.paths:
                if self._stop.is_set():
                    break
                if not os.path.isdir(path):
                    continue
                for root, dirs, files in os.walk(path):
                    if self._stop.is_set():
                        break
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            mtime = os.path.getmtime(fpath)
                            last = self._known.get(fpath)
                            if last is not None and mtime > last:
                                if self.callback:
                                    self.callback(fpath)
                            self._known[fpath] = mtime
                        except OSError:
                            continue
            time.sleep(self.interval)
