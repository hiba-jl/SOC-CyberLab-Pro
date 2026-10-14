from pathlib import Path
import json
import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC CyberLab Pro", page_icon="🛡️", layout="wide")
st.title("🛡️ SOC CyberLab Pro")
st.caption("Educational SIEM pipeline · Authentication anomaly detection · Synthetic lab data")

report_path = Path("reports/alerts.json")
if not report_path.exists():
    st.warning("No report found yet. Run the detector command shown in README.md first.")
    st.stop()

data = json.loads(report_path.read_text(encoding="utf-8"))
alerts = data.get("alerts", [])
invalid = data.get("invalid_lines", [])
df = pd.DataFrame(alerts)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts", len(alerts))
c2.metric("Critical", sum(a.get("severity") == "CRITICAL" for a in alerts))
c3.metric("Source IPs", df["source_ip"].nunique() if not df.empty else 0)
c4.metric("Invalid lines", len(invalid))

st.subheader("Alert triage")
if df.empty:
    st.success("No threshold-crossing activity found in this report.")
else:
    severities = ["All"] + sorted(df["severity"].dropna().unique().tolist())
    selected = st.selectbox("Severity filter", severities)
    shown = df if selected == "All" else df[df["severity"] == selected]
    columns = [c for c in ["alert_id", "timestamp", "severity", "source_ip", "failed_attempts", "rule_id", "mitre", "title"] if c in shown]
    st.dataframe(shown[columns], use_container_width=True, hide_index=True)
    st.bar_chart(shown.groupby("source_ip")["failed_attempts"].max())
    st.download_button("Download displayed alerts (CSV)", shown.to_csv(index=False).encode("utf-8-sig"),
                       file_name="soc-alerts.csv", mime="text/csv")

with st.expander("Detection evidence and recommended action"):
    if df.empty:
        st.write("No alerts to investigate.")
    else:
        for alert in alerts:
            st.markdown(f"**{alert['alert_id']} — {alert['severity']} — {alert['source_ip']}**")
            st.write("Evidence:", " · ".join(alert.get("evidence", [])))
            st.write("Recommended next step:", alert.get("recommended_action", "Review relevant logs."))

with st.expander("Malformed or unsupported log lines"):
    if invalid:
        st.dataframe(pd.DataFrame(invalid), use_container_width=True, hide_index=True)
    else:
        st.write("No invalid lines were reported.")
