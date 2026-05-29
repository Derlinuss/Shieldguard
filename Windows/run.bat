@echo off
title ShieldGuard Antivirus
cd /d "%~dp0"

echo [*] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo [*] Checking dependencies...
pip install -r requirements.txt --quiet 2>nul
if %errorlevel% neq 0 (
    echo [*] Installing dependencies from requirements.txt...
    pip install -r requirements.txt --quiet
)

echo [*] Starting ShieldGuard Antivirus...
echo.
python main.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] ShieldGuard exited with code %errorlevel%.
    pause
)
