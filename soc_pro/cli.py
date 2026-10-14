"""Command-line interface for SOC CyberLab Pro."""
import argparse
import csv
import json
from pathlib import Path
from .detector import DetectionConfig, analyze_file

def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze authentication logs for brute-force patterns.")
    parser.add_argument("--input", required=True, help="Path to input log file")
    parser.add_argument("--out", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--window", type=int, default=5, help="Rolling time window in minutes")
    parser.add_argument("--alert-threshold", type=int, default=3, help="Failed attempts to trigger ALERT")
    parser.add_argument("--critical-threshold", type=int, default=5, help="Failed attempts to trigger CRITICAL")
    args = parser.parse_args()

    config = DetectionConfig(args.window, args.alert_threshold, args.critical_threshold)
    config.validate()
    result = analyze_file(args.input, config)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": {
            "total_lines": result.total_lines,
            "valid_failed_events": result.valid_failed_events,
            "invalid_lines": len(result.invalid_lines),
            "alerts": len(result.alerts),
        },
        "alerts": [a.to_dict() for a in result.alerts],
        "invalid_lines": result.invalid_lines,
    }
    json_path = out / "alerts.json"
    csv_path = out / "alerts.csv"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    columns = ["alert_id", "timestamp", "source_ip", "severity", "failed_attempts",
               "window_minutes", "rule_id", "mitre", "title", "recommended_action"]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for alert in result.alerts:
            row = alert.to_dict()
            row["evidence"] = " | ".join(row["evidence"])
            writer.writerow({key: row.get(key, "") for key in columns})
    print("=" * 58)
    print("SOC CYBERLAB PRO — AUTHENTICATION DETECTOR")
    print("=" * 58)
    print(f"Input file         : {args.input}")
    print(f"Total lines        : {result.total_lines}")
    print(f"Valid failed events: {result.valid_failed_events}")
    print(f"Invalid lines      : {len(result.invalid_lines)}")
    print(f"Alerts emitted     : {len(result.alerts)}")
    for alert in result.alerts:
        print(f"[{alert.severity}] {alert.rule_id} | {alert.source_ip} | failures={alert.failed_attempts} | {alert.timestamp}")
    print(f"JSON report        : {json_path}")
    print(f"CSV report         : {csv_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
