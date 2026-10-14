from soc_pro.detector import DetectionConfig, analyze_lines

def line(minute, ip="192.168.1.40", user="alice"):
    return f"2026-10-14 12:{minute:02d}:00 LOGIN_FAILED src={ip} user={user}"

def test_below_threshold_does_not_alert():
    result = analyze_lines([line(0), line(1)], DetectionConfig())
    assert result.alerts == []

def test_alert_threshold():
    result = analyze_lines([line(0), line(1), line(2)], DetectionConfig())
    assert len(result.alerts) == 1
    assert result.alerts[0].severity == "ALERT"
    assert result.alerts[0].failed_attempts == 3

def test_critical_threshold():
    result = analyze_lines([line(0), line(1), line(2), line(3), line(4)], DetectionConfig())
    assert len(result.alerts) == 1
    assert result.alerts[0].severity == "CRITICAL"
    assert result.alerts[0].failed_attempts == 5

def test_window_expires_old_events():
    lines = [line(0), line(1), line(2), line(10)]
    result = analyze_lines(lines, DetectionConfig(window_minutes=5, alert_threshold=3, critical_threshold=5))
    assert len(result.alerts) == 1
    assert result.alerts[0].failed_attempts == 3

def test_invalid_ip_is_reported():
    result = analyze_lines(["2026-10-14 12:00:00 LOGIN_FAILED src=999.1.1.1 user=alice"])
    assert len(result.invalid_lines) == 1
    assert result.alerts == []

def test_unrecognized_line_is_reported():
    result = analyze_lines(["this is not a supported log"])
    assert len(result.invalid_lines) == 1

def test_separate_ips_are_not_combined():
    result = analyze_lines([line(0), line(1), line(2, ip="192.168.1.41")])
    assert result.alerts == []


# ---- Rule 2: password spraying -------------------------------------------
def rule_ids(result):
    return {a.rule_id for a in result.alerts}

def test_password_spraying_detected():
    lines = [line(0, user="alice"), line(1, user="bob"), line(2, user="carol")]
    result = analyze_lines(lines)
    assert "AUTH_PASSWORD_SPRAYING" in rule_ids(result)
    spray = next(a for a in result.alerts if a.rule_id == "AUTH_PASSWORD_SPRAYING")
    assert spray.severity == "ALERT"
    assert spray.mitre.startswith("T1110.003")

def test_spraying_critical_with_many_users():
    lines = [line(i, user=f"user{i}") for i in range(5)]
    result = analyze_lines(lines)
    spray = next(a for a in result.alerts if a.rule_id == "AUTH_PASSWORD_SPRAYING")
    assert spray.severity == "CRITICAL"

def test_same_user_is_not_spraying():
    result = analyze_lines([line(0), line(1), line(2), line(3)])
    assert "AUTH_PASSWORD_SPRAYING" not in rule_ids(result)

# ---- Rule 3: success after failures --------------------------------------
def success(minute, ip="192.168.1.40", user="alice"):
    return f"2026-10-14 12:{minute:02d}:00 LOGIN_SUCCESS src={ip} user={user}"

def test_success_after_failures_detected():
    result = analyze_lines([line(0), line(1), line(2), success(3)])
    assert "AUTH_SUCCESS_AFTER_FAILURES" in rule_ids(result)
    alert = next(a for a in result.alerts if a.rule_id == "AUTH_SUCCESS_AFTER_FAILURES")
    assert alert.severity == "CRITICAL"
    assert alert.mitre.startswith("T1078")

def test_success_without_failures_is_normal():
    result = analyze_lines([success(0), success(1)])
    assert result.alerts == []

def test_success_before_failures_does_not_alert():
    result = analyze_lines([success(0), line(1), line(2), line(3)])
    assert "AUTH_SUCCESS_AFTER_FAILURES" not in rule_ids(result)

def test_old_failures_outside_window_do_not_count():
    result = analyze_lines([line(0), line(1), line(2), success(30)])
    assert "AUTH_SUCCESS_AFTER_FAILURES" not in rule_ids(result)
