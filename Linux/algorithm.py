import hashlib
import json
import os
import struct
import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
import re
import tempfile
from datetime import datetime, timedelta

SIGNATURE_DB = {
    "hashes": {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"name": "EICAR-Test", "type": "test", "severity": "info"},
        "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854": {"name": "Trojan.Generic.1", "type": "trojan", "severity": "high"},
        "b4c0d44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b853": {"name": "Ransomware.WannaCry", "type": "ransomware", "severity": "critical"},
        "c5d0e44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b852": {"name": "Worm.Stuxnet", "type": "worm", "severity": "critical"},
        "d6e0f44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b851": {"name": "Adware.Bundle", "type": "adware", "severity": "low"},
        "275a021bbfb6489e54d4718f7f8b5a2e6b1f2e5f9c8d4e3a2b1c6d5e4f3a2b1c": {"name": "Backdoor.DarkComet", "type": "backdoor", "severity": "critical"},
        "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2": {"name": "Keylogger.Agent", "type": "keylogger", "severity": "high"},
        "f1e2d3c4b5a69788796a5b4c3d2e1f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": {"name": "Miner.CoinMiner", "type": "miner", "severity": "medium"},
    },
    "patterns": [
        {"name": "Ransomware-Notes", "pattern": b"your files have been encrypted", "severity": "critical", "type": "ransomware"},
        {"name": "Ransomware-Notes2", "pattern": b"pay.*bitcoin.*decrypt", "severity": "critical", "type": "ransomware"},
        {"name": "Shellcode-Exec", "pattern": b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68", "severity": "high", "type": "shellcode"},
        {"name": "PowerShell-Empire", "pattern": b"Invoke-Empire", "severity": "high", "type": "backdoor"},
        {"name": "Mimikatz", "pattern": b"mimikatz", "severity": "critical", "type": "credential-theft"},
        {"name": "CryptoLocker", "pattern": b"CryptoLocker", "severity": "critical", "type": "ransomware"},
        {"name": "DarkComet-RAT", "pattern": b"DarkComet", "severity": "critical", "type": "rat"},
        {"name": "NjRAT", "pattern": b"NjRAT", "severity": "high", "type": "rat"},
        {"name": "JS-Obfuscation", "pattern": b"eval(atob(", "severity": "medium", "type": "obfuscated"},
        {"name": "Base64-Exec", "pattern": b"[A-Za-z0-9+/]{50,}={0,2}", "severity": "low", "type": "encoded"},
        {"name": "Linux-ELF-Exec", "pattern": b"\\x7fELF", "severity": "low", "type": "executable"},
    ],
    "heuristic_rules": [
        {"name": "Suspect-Entropy", "description": "High entropy indicating packed/encrypted payload", "weight": 15},
        {"name": "Many-Imports", "description": "Suspicious number of imported functions", "weight": 10},
        {"name": "Network-APIs", "description": "Contains socket/network API calls", "weight": 20},
        {"name": "Process-Injection", "description": "Contains process injection APIs", "weight": 30},
        {"name": "Registry-Persistence", "description": "Modifies auto-run registry keys", "weight": 25},
        {"name": "File-Encryption-APIs", "description": "Contains file encryption APIs", "weight": 30},
        {"name": "Anti-Debug", "description": "Contains anti-debugging checks", "weight": 20},
        {"name": "Hidden-Attributes", "description": "Sets hidden/system file attributes", "weight": 15},
    ],
    "suspicious_extensions": [
        ".elf", ".so", ".o", ".ko", ".bin", ".run", ".sh", ".bash",
        ".py", ".pl", ".php", ".rb", ".js", ".jar", ".class",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".docm", ".xlsm", ".pptm",
    ],
    "dangerous_imports_pe": [
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "SetWindowsHookEx", "RegisterHotKey", "GetAsyncKeyState",
        "CryptEncrypt", "CryptDecrypt", "WinExec", "ShellExecute",
        "RegSetValueEx", "RegCreateKeyEx", "StartService",
        "WmiExecQuery", "CreateService", "OpenSCManager",
    ],
}

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "virus_db.json")
DB_UPDATE_URL = "https://example.com/antivirus/updates/latest.json"
DB_CACHE_TTL = timedelta(hours=24).total_seconds()


def load_database():
    db = dict(SIGNATURE_DB)
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, "r") as f:
                custom = json.load(f)
            for key in ["hashes", "patterns", "heuristic_rules"]:
                if key in custom:
                    db[key].update(custom[key]) if isinstance(db[key], dict) else db[key].extend(custom[key])
        except (json.JSONDecodeError, IOError):
            pass
    return db


def save_database(db):
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)


def update_database_from_web():
    db = load_database()
    try:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(DB_UPDATE_URL, headers={"User-Agent": "ShieldGuard-AV/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            if resp.status == 200:
                remote = json.loads(resp.read().decode())
                for key in ["hashes", "patterns", "heuristic_rules"]:
                    if key in remote:
                        if isinstance(db[key], dict):
                            db[key].update(remote[key])
                        else:
                            db[key].extend(remote[key])
                save_database(db)
                return True, "Database updated successfully"
    except (urllib.error.URLError, json.JSONDecodeError, ssl.SSLError, socket.error) as e:
        return False, str(e)
    return False, "Update source unavailable"


def get_file_hash(filepath, algorithm="sha256", blocksize=65536):
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(blocksize), b""):
                h.update(block)
        return h.hexdigest()
    except (IOError, PermissionError):
        return None


def hash_lookup(filepath):
    db = load_database()
    h = get_file_hash(filepath)
    if h and h in db["hashes"]:
        entry = db["hashes"][h]
        return {"detected": True, "method": "hash", "name": entry["name"], "type": entry["type"], "severity": entry["severity"], "hash": h}
    for algo in ("sha1", "md5"):
        h = get_file_hash(filepath, algorithm=algo)
        if h and h in db["hashes"]:
            entry = db["hashes"][h]
            return {"detected": True, "method": "hash", "name": entry["name"], "type": entry["type"], "severity": entry["severity"], "hash": h}
    return {"detected": False, "method": "hash"}


def scan_patterns(data, db=None):
    if db is None:
        db = load_database()
    results = []
    for sig in db["patterns"]:
        try:
            if sig["pattern"] in data:
                results.append({"detected": True, "method": "pattern", "name": sig["name"], "type": sig["type"], "severity": sig["severity"]})
        except TypeError:
            continue
    return results


def quick_scan_file(filepath, db=None):
    if db is None:
        db = load_database()
    results = []
    hash_result = hash_lookup(filepath)
    if hash_result["detected"]:
        results.append(hash_result)
    try:
        with open(filepath, "rb") as f:
            header = f.read(5 * 1024 * 1024)
        pattern_results = scan_patterns(header, db)
        results.extend(pattern_results)
    except (IOError, PermissionError):
        pass
    return results if results else [{"detected": False, "method": "quick"}]


def calculate_entropy(data):
    if not data:
        return 0.0
    from collections import Counter
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * (count / length).bit_length() for count in counter.values())
    return abs(entropy)


def heuristic_scan(filepath):
    db = load_database()
    score = 0
    flags = []
    try:
        with open(filepath, "rb") as f:
            data = f.read(2 * 1024 * 1024)
    except (IOError, PermissionError):
        return {"score": 0, "flags": [], "verdict": "clean"}
    entropy = calculate_entropy(data[:4096])
    if entropy > 6.5:
        score += 15
        flags.append("Suspect-Entropy")
    dangerous_strings = [
        (b"CreateRemoteThread", "Process-Injection"), (b"WriteProcessMemory", "Process-Injection"),
        (b"VirtualAllocEx", "Process-Injection"), (b"SetWindowsHookEx", "Keylogging"),
        (b"GetAsyncKeyState", "Keylogging"), (b"CryptEncrypt", "File-Encryption-APIs"),
        (b"CryptDecrypt", "File-Encryption-APIs"), (b"RegSetValueEx", "Registry-Persistence"),
        (b"RegCreateKeyEx", "Registry-Persistence"), (b"IsDebuggerPresent", "Anti-Debug"),
        (b"WinExec", "Suspicious-Exec"), (b"ShellExecute", "Suspicious-Exec"),
        (b"socket", "Network-APIs"), (b"connect(", "Network-APIs"),
        (b"recv(", "Network-APIs"), (b"SetFileAttributesA", "Hidden-Attributes"),
        (b"FILE_ATTRIBUTE_HIDDEN", "Hidden-Attributes"),
        (b"ptrace", "Anti-Debug"), (b"sys_open", "Suspicious-Syscall"),
        (b"SYS_ptrace", "Anti-Debug"),
    ]
    for pattern, flag in dangerous_strings:
        if pattern in data:
            score += next((r["weight"] for r in db["heuristic_rules"] if r["name"] == flag), 15)
            if flag not in flags:
                flags.append(flag)
    if b"KERNEL32.dll" in data or b"kernel32" in data:
        import_count = data.count(b"ExitProcess") + data.count(b"CreateFile") + data.count(b"ReadFile") + data.count(b"WriteFile")
        if import_count > 20:
            score += 10
            flags.append("Many-Imports")
    verdict = "clean"
    if score >= 70:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    elif score >= 15:
        verdict = "low_risk"
    return {"score": score, "flags": flags, "verdict": verdict}


def web_search_hash(filehash, api_key=None):
    if not api_key:
        env_key = os.environ.get("VT_API_KEY") or os.environ.get("SHIELDGUARD_API_KEY")
        api_key = env_key or "demo"
    url = f"https://www.virustotal.com/api/v3/files/{filehash}"
    headers = {"User-Agent": "ShieldGuard-AV/1.0", "x-apikey": api_key}
    try:
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {"detected": stats.get("malicious", 0) > 0, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "undetected": stats.get("undetected", 0), "harmless": stats.get("harmless", 0), "source": "virustotal"}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"detected": False, "source": "virustotal", "error": "not_found"}
        if e.code == 401:
            return {"detected": False, "source": "virustotal", "error": "invalid_key"}
        return {"detected": False, "source": "virustotal", "error": str(e.code)}
    except (urllib.error.URLError, socket.error, ssl.SSLError) as e:
        return {"detected": False, "source": "virustotal", "error": str(e)}
    return {"detected": False, "source": "virustotal"}


def web_search_unknown_file(filepath, api_key=None):
    h = get_file_hash(filepath)
    if not h:
        return {"detected": False, "error": "cannot_hash"}
    return web_search_hash(h, api_key)


def full_analysis(filepath):
    result = {"filepath": filepath, "filename": os.path.basename(filepath), "size": 0, "detected": False, "threats": [], "heuristic": None, "magic": None, "timestamp": datetime.now().isoformat()}
    try:
        result["size"] = os.path.getsize(filepath)
    except OSError:
        pass
    hash_r = hash_lookup(filepath)
    if hash_r["detected"]:
        result["detected"] = True
        result["threats"].append(hash_r)
    try:
        with open(filepath, "rb") as f:
            header = f.read(5 * 1024 * 1024)
        pattern_r = scan_patterns(header)
        for p in pattern_r:
            if p["detected"]:
                result["detected"] = True
                result["threats"].append(p)
    except (IOError, PermissionError):
        pass
    heur = heuristic_scan(filepath)
    result["heuristic"] = heur
    if heur["verdict"] in ("malicious", "suspicious"):
        result["detected"] = True
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
        result["magic"] = magic.hex()
    except (IOError, PermissionError):
        pass
    result["web_lookup_available"] = True
    return result


WHITELIST_PATHS = set()
WHITELIST_HASHES = set()

def add_whitelist(filepath):
    WHITELIST_PATHS.add(os.path.abspath(filepath))
    h = get_file_hash(filepath)
    if h:
        WHITELIST_HASHES.add(h)

def is_whitelisted(filepath):
    if os.path.abspath(filepath) in WHITELIST_PATHS:
        return True
    h = get_file_hash(filepath)
    return h in WHITELIST_HASHES if h else False
