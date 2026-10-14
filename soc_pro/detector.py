"""Small, testable authentication-log detector for a defensive SOC lab."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import ipaddress
import re
from pathlib import Path
from typing import Iterable

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<event>LOGIN_FAILED|LOGIN_SUCCESS) src=(?P<ip>\S+) user=(?P<user>\S+)$"
)

@dataclass(frozen=True)
class DetectionConfig:
    window_minutes: int = 5
    alert_threshold: int = 3
    critical_threshold: int = 5
    spray_user_threshold: int = 3      # distinct usernames from one IP -> ALERT
    spray_critical_users: int = 5      # distinct usernames from one IP -> CRITICAL

    def validate(self) -> None:
        if self.window_minutes < 1:
            raise ValueError("window_minutes must be >= 1")
        if self.alert_threshold < 1:
            raise ValueError("alert_threshold must be >= 1")
        if self.critical_threshold < self.alert_threshold:
            raise ValueError("critical_threshold must be >= alert_threshold")
        if self.spray_user_threshold < 2:
            raise ValueError("spray_user_threshold must be >= 2")
        if self.spray_critical_users < self.spray_user_threshold:
            raise ValueError("spray_critical_users must be >= spray_user_threshold")

@dataclass
class Alert:
    alert_id: str
    timestamp: str
    source_ip: str
    severity: str
    failed_attempts: int
    window_minutes: int
    rule_id: str
    title: str
    evidence: list[str]
    recommended_action: str
    mitre: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class AnalysisResult:
    alerts: list[Alert]
    invalid_lines: list[dict]
    total_lines: int
    valid_failed_events: int

def parse_line(line: str) -> tuple[datetime, str, str, str] | None:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    timestamp = datetime.strptime(match.group("timestamp"), TIMESTAMP_FORMAT)
    event = match.group("event")
    ip = str(ipaddress.IPv4Address(match.group("ip")))
    username = match.group("user")
    return timestamp, event, ip, username

def analyze_lines(lines: Iterable[str], config: DetectionConfig | None = None) -> AnalysisResult:
    config = config or DetectionConfig()
    config.validate()
    events: dict[str, list[tuple[datetime, str]]] = defaultdict(list)      # failed logins
    successes: dict[str, list[tuple[datetime, str]]] = defaultdict(list)   # successful logins
    invalid_lines: list[dict] = []
    total = 0
    valid = 0

    for line_no, raw in enumerate(lines, start=1):
        total += 1
        line = raw.strip()
        if not line:
            continue
        try:
            parsed = parse_line(line)
            if parsed is None:
                raise ValueError("Unrecognized log format")
            timestamp, event, ip, username = parsed
            if event == "LOGIN_FAILED":
                events[ip].append((timestamp, username))
                valid += 1
            else:
                successes[ip].append((timestamp, username))
        except (ValueError, OverflowError) as exc:
            invalid_lines.append({"line": line_no, "raw": line, "reason": str(exc)})

    alerts: list[Alert] = []
    threshold = config.alert_threshold
    for ip, ip_events in sorted(events.items()):
        ip_events.sort(key=lambda item: item[0])
        best: tuple[int, datetime, list[tuple[datetime, str]]] | None = None
        left = 0
        for right, (timestamp, _username) in enumerate(ip_events):
            while left <= right and timestamp - ip_events[left][0] > timedelta(minutes=config.window_minutes):
                left += 1
            count = right - left + 1
            if count >= threshold and (best is None or count > best[0]):
                best = (count, timestamp, ip_events[left:right + 1])
        if best is None:
            continue
        count, timestamp, evidence_events = best
        severity = "CRITICAL" if count >= config.critical_threshold else "ALERT"
        user_names = sorted({u for _, u in evidence_events})
        alerts.append(Alert(
            alert_id=f"BF-{timestamp.strftime('%Y%m%d%H%M%S')}-{ip.replace('.', '-')}",
            timestamp=timestamp.strftime(TIMESTAMP_FORMAT),
            source_ip=ip,
            severity=severity,
            failed_attempts=count,
            window_minutes=config.window_minutes,
            rule_id="AUTH_BRUTE_FORCE_5MIN",
            title="Repeated failed authentication attempts",
            evidence=[f"{count} failed login events in {config.window_minutes} minutes",
                      f"Observed username(s): {', '.join(user_names)}"],
            recommended_action="Validate whether activity is expected; review surrounding logs; if unauthorized, follow the approved account/IP containment process.",
            mitre="T1110.001 - Brute Force: Password Guessing",
        ))

    alerts.extend(_detect_password_spraying(events, config))
    alerts.extend(_detect_success_after_failures(events, successes, config))
    alerts.sort(key=lambda a: (a.timestamp, a.rule_id, a.source_ip))
    return AnalysisResult(alerts, invalid_lines, total, valid)

def _detect_password_spraying(events: dict[str, list[tuple[datetime, str]]],
                              config: DetectionConfig) -> list[Alert]:
    """One source IP failing against many DIFFERENT usernames within the window."""
    window = timedelta(minutes=config.window_minutes)
    found: list[Alert] = []
    for ip, ip_events in sorted(events.items()):
        ordered = sorted(ip_events, key=lambda item: item[0])
        best: tuple[int, datetime, list[tuple[datetime, str]]] | None = None
        left = 0
        for right, (timestamp, _user) in enumerate(ordered):
            while left <= right and timestamp - ordered[left][0] > window:
                left += 1
            chunk = ordered[left:right + 1]
            distinct = len({u for _, u in chunk})
            if distinct >= config.spray_user_threshold and (best is None or distinct > best[0]):
                best = (distinct, timestamp, chunk)
        if best is None:
            continue
        distinct, timestamp, chunk = best
        users = sorted({u for _, u in chunk})
        found.append(Alert(
            alert_id=f"SPRAY-{timestamp.strftime('%Y%m%d%H%M%S')}-{ip.replace('.', '-')}",
            timestamp=timestamp.strftime(TIMESTAMP_FORMAT),
            source_ip=ip,
            severity="CRITICAL" if distinct >= config.spray_critical_users else "ALERT",
            failed_attempts=len(chunk),
            window_minutes=config.window_minutes,
            rule_id="AUTH_PASSWORD_SPRAYING",
            title="Possible password spraying (many usernames from one IP)",
            evidence=[f"{distinct} distinct usernames targeted in {config.window_minutes} minutes",
                      f"{len(chunk)} failed login events",
                      f"Observed username(s): {', '.join(users)}"],
            recommended_action="Check whether these accounts exist and are in scope; look for any successful login from this IP; if unauthorized, follow the approved IP containment process and review password policy / MFA.",
            mitre="T1110.003 - Brute Force: Password Spraying",
        ))
    return found


def _detect_success_after_failures(events: dict[str, list[tuple[datetime, str]]],
                                   successes: dict[str, list[tuple[datetime, str]]],
                                   config: DetectionConfig) -> list[Alert]:
    """A successful login right after a burst of failures from the same IP."""
    window = timedelta(minutes=config.window_minutes)
    found: list[Alert] = []
    for ip, ok_events in sorted(successes.items()):
        failures = sorted(events.get(ip, []), key=lambda item: item[0])
        best: tuple[int, datetime, str, list[tuple[datetime, str]]] | None = None
        for ok_time, ok_user in sorted(ok_events, key=lambda item: item[0]):
            recent = [f for f in failures if timedelta(0) <= ok_time - f[0] <= window]
            if len(recent) >= config.alert_threshold and (best is None or len(recent) > best[0]):
                best = (len(recent), ok_time, ok_user, recent)
        if best is None:
            continue
        count, ok_time, ok_user, recent = best
        found.append(Alert(
            alert_id=f"SUCC-{ok_time.strftime('%Y%m%d%H%M%S')}-{ip.replace('.', '-')}",
            timestamp=ok_time.strftime(TIMESTAMP_FORMAT),
            source_ip=ip,
            severity="CRITICAL",
            failed_attempts=count,
            window_minutes=config.window_minutes,
            rule_id="AUTH_SUCCESS_AFTER_FAILURES",
            title="Successful login after repeated failures (possible compromise)",
            evidence=[f"{count} failed logins in the {config.window_minutes} minutes before a success",
                      f"Successful login for user: {ok_user}",
                      f"Failed attempts targeted: {', '.join(sorted({u for _, u in recent}))}"],
            recommended_action="Treat the account as potentially compromised: verify with the user, review activity after the login, and if unauthorized follow the approved process (reset credentials, revoke sessions, block the source IP).",
            mitre="T1078 - Valid Accounts",
        ))
    return found


def analyze_file(path: str | Path, config: DetectionConfig | None = None) -> AnalysisResult:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        return analyze_lines(handle, config)
