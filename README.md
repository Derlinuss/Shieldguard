# ShieldGuard Antivirus

A cross-platform antivirus suite with terminal and GUI interfaces for **Windows**, **macOS**, and **Linux**.

> **Note:** The GUI frontend was designed with AI assistance. Everything else — detection engine, scanner, quarantine, real-time protection, launchers — was built from scratch.  
> **55% me · 45% AI**

## Features

- Multi-engine detection: SHA-256 hash DB, byte-pattern matching, heuristic scoring (entropy + dangerous API analysis)
- VirusTotal online hash lookup
- Real-time file protection (folder monitoring)
- Quarantine management (restore / delete permanently)
- Auto-updating virus definitions
- Scan reports and activity logs
- Dark-themed modern GUI (tkinter, Canvas-based)
- Terminal menu (press `G` to launch GUI)

## Platform Support

| Platform | Terminal | GUI | Launcher |
|----------|----------|-----|----------|
| Windows  | `Windows\main.py` | `Windows\gui.py` | `run.bat` |
| macOS    | `MacOS\main.py` | `MacOS\gui.py` | `run.sh` |
| Linux    | `Linux\main.py` | `Linux\gui.py` | `run.sh` |

## Quick Start

### Windows
```bat
cd Windows
run.bat
```

### macOS / Linux
```sh
cd MacOS   # or cd Linux
chmod +x run.sh
./run.sh
```

## Requirements

- Python 3.8+
- `colorama` (installed automatically by the launcher)

## Project Structure

```
ShieldGuard/
├── Windows/           # Windows client
│   ├── algorithm.py   # Detection engine
│   ├── scanner.py     # File scanner
│   ├── antivirus.py   # Core logic
│   ├── gui.py         # GUI (tkinter)
│   ├── main.py        # Terminal entry
│   ├── ui.py          # Terminal UI helpers
│   ├── run.bat        # Launcher
│   └── requirements.txt
├── MacOS/             # macOS client (mirrors Windows)
├── Linux/             # Linux client (mirrors Windows)
├── quarantine/        # Quarantined files
└── README.md
```

## License

MIT
