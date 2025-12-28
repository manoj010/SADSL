# SADSL: Suspicious Activity Detector from System Logs

## Overview
SADSL is a Python-based tool that analyzes system logs to detect suspicious activities, including:
- Multiple failed login attempts (brute-force detection)
- Unauthorized access to restricted URLs (e.g., /admin, /config)

It also provides analytics and exports reports in Excel and PDF format.

---

## Project Structure
```bash
SADSL/
│
├── logs/ # Log files
│ └── sample.log
├── config/ # Detection rules
│ └── rules.json
├── src/ # Python source code
│ ├── main.py # Entry point
│ ├── log_reader.py # Log reading/parsing
│ ├── detector.py # Suspicious activity detection
│ ├── utils.py # Helpers (timestamp parsing, URL counting, etc.)
│ ├── db.py # SQLite integration
│ ├── reporting.py # Trend chart generation
│ └── exporter.py # Excel & PDF report export
├── sadsl.db # SQLite database (generated)
└── sadsl_report.xlxs # Excel report (generated)
```

---

## Installation

1. **Clone the repository** (or copy files locally)
2. **Install dependencies**:

```bash
pip install openpyxl reportlab matplotlib
```

## Usage
```bash
python src/main.py
```
