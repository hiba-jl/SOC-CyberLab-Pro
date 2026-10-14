# SOC CyberLab Pro — Python SIEM Mini-Lab

A defensive, educational SOC project for analyzing authentication logs, detecting brute-force patterns, producing structured alerts, and presenting results in a Streamlit dashboard.

## Features
- Parses synthetic authentication logs.
- Detects repeated failed logins per source IP within a configurable time window.
- Uses configurable alert and critical thresholds.
- Validates timestamps and IPv4 addresses; reports malformed lines.
- Exports JSON and CSV alerts.
- Includes repeatable automated tests.
- Includes sample logs and a Streamlit dashboard.
- Runs locally; no external service or real attack traffic required.

## Important
This is a learning/portfolio project, not a production SIEM. Use only logs you are authorized to analyze. The included samples are synthetic.

## Quick start (Windows)
Open PowerShell in this folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m soc_pro.cli --input samples/auth.log --out reports
.\.venv\Scripts\python.exe -m streamlit run dashboard.py
```

## Log format
```text
2026-10-14 12:00:00 LOGIN_FAILED src=192.168.1.40 user=alice
```

## Detection logic
For each source IP, failed-login events are counted in a rolling time window. At or above the alert threshold, an alert is emitted; at or above the critical threshold, severity is CRITICAL. Each IP gets one highest-severity alert per analysis run to avoid duplicate threshold alerts.

## Portfolio evidence to add
1. Screenshot of the dashboard with synthetic alerts.
2. Test output from `pytest`.
3. A short incident report explaining the alert, evidence, triage steps, and containment recommendation.
4. A diagram showing log source → parser → detection rule → alert JSON/CSV → dashboard.
