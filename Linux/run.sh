#!/bin/bash
# ShieldGuard Antivirus - Linux Launcher

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

echo "[*] Checking Python installation..."
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 is not installed."
    echo "Install it using: sudo apt install python3  (or your distro's equivalent)"
    exit 1
fi

echo "[*] Checking dependencies..."
python3 -c "import colorama" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[*] Installing colorama for colored output..."
    pip3 install colorama --quiet
fi

echo "[*] Starting ShieldGuard Antivirus..."
echo ""
python3 main.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[ERROR] ShieldGuard exited with code $?."
    read -rp "Press Enter to close..."
fi
