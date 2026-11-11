# SOC CyberLab Pro — Python SIEM Mini-Lab

A defensive, educational SOC project: it parses authentication logs, detects **brute force**, **password spraying** and **successful logins after repeated failures**, maps every alert to **MITRE ATT&CK**, exports structured alerts (JSON / CSV) and presents them in a **Streamlit** triage dashboard.

> **Learning / portfolio project**, not a production SIEM. The included logs are synthetic. Only analyze logs you are authorized to analyze.

## Detection rules

| Rule | What it detects | Default trigger | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| `AUTH_BRUTE_FORCE` | Many failed logins from one IP | ≥ 3 failures in 5 min (≥ 5 → critical) | ALERT / CRITICAL | T1110.001 Password Guessing |
| `AUTH_PASSWORD_SPRAYING` | One IP failing on many **different** accounts | ≥ 3 distinct accounts in 5 min | ALERT / CRITICAL | T1110.003 Password Spraying |
| `AUTH_SUCCESS_AFTER_FAILURES` | A **successful** login preceded by repeated failures from the same IP (possible compromise) | success after ≥ 3 failures in 5 min | CRITICAL | T1110 Brute Force, T1078 Valid Accounts |

All thresholds and the time window are configurable from the command line.

## Pipeline

```
 Authentication log ──▶ Parser ──▶ Detection rules ──▶ Alerts (JSON / CSV) ──▶ Streamlit dashboard
                       (validates     (rolling time      (severity, evidence,     (filters by severity
                        timestamps,     window per IP)     MITRE mapping,           and rule, MITRE chart,
                        IPv4, format)                      recommended action)      triage details)
```

## Features
- Parses `LOGIN_FAILED` and `LOGIN_SUCCESS` events.
- Rolling time-window detection per source IP, with three rules mapped to MITRE ATT&CK.
- Each alert includes evidence (counts, targeted accounts) and a recommended response action.
- Validates timestamps and IPv4 addresses; malformed lines are reported, not silently dropped.
- JSON and CSV export.
- Streamlit dashboard: severity and rule filters, "possible compromise" counter, alerts per MITRE technique.
- **14 automated pytest tests** covering thresholds, time windows, spraying, success-after-failures and MITRE mapping.

## Quick start (Windows)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m soc_pro.cli --input samples/attack_scenarios.log --out reports
.\.venv\Scripts\python.exe -m streamlit run dashboard.py
```

Optional parameters: `--window 5 --alert-threshold 3 --critical-threshold 5 --spray-threshold 3`

## Log format

```text
2026-10-14 12:00:00 LOGIN_FAILED src=192.168.1.40 user=alice
2026-10-14 12:02:30 LOGIN_SUCCESS src=192.168.1.40 user=alice
```

## Example run

`samples/attack_scenarios.log` contains three synthetic scenarios: a brute force on `admin`, a password spraying across five accounts, and a successful login on `alice` right after three failures.

```text
Total lines        : 15
Valid failed events: 13
Valid success events: 2
Invalid lines      : 0
Alerts emitted     : 5
[ALERT] AUTH_BRUTE_FORCE | 192.168.1.40 | failures=3 | T1110.001 | 2026-10-14 12:02:00
[CRITICAL] AUTH_SUCCESS_AFTER_FAILURES | 192.168.1.40 | failures=3 | T1110, T1078 | 2026-10-14 12:02:30
[CRITICAL] AUTH_BRUTE_FORCE | 192.168.1.99 | failures=5 | T1110.001 | 2026-10-14 12:07:00
[CRITICAL] AUTH_BRUTE_FORCE | 10.0.0.66 | failures=5 | T1110.001 | 2026-10-14 13:01:20
[CRITICAL] AUTH_PASSWORD_SPRAYING | 10.0.0.66 | failures=5 | T1110.003 | 2026-10-14 13:01:20
```

The legitimate login of `bob` (no prior failures) raises no alert. The spraying source also crosses the brute-force threshold, so both rules fire, as they would in a real SIEM.

## Tests

```text
14 passed
```

## Project structure

```
soc_pro/detector.py      parsing + the three detection rules + MITRE mapping
soc_pro/cli.py           command-line analysis and JSON/CSV export
dashboard.py             Streamlit triage dashboard
tests/test_detector.py   automated tests
samples/                 synthetic logs (normal, invalid lines, attack scenarios)
```

## Limitations and next steps
- Custom log format; next step: parse real Linux `auth.log` / Windows Security events (4625 / 4624).
- Detection is per source IP; distributed attacks from many IPs are not correlated yet.
- Possible additions: IP reputation enrichment, alert export to TheHive.

## Author

Hiba Jelloul, [github.com/hiba-jl](https://github.com/hiba-jl)
