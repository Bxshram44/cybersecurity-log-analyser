import streamlit as st
import pandas as pd

from log_analyser import (
    load_logs,
    calculate_statistics,
    analyse_ip_addresses,
    analyse_usernames,
    detect_suspicious_activity,
)

st.set_page_config(
    page_title="Cybersecurity Log Analyser",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Cybersecurity Log Analyser")
st.write(
    "Analyse simulated login activity, identify suspicious "
    "patterns and investigate security alerts."
)

st.sidebar.header("Settings")

threshold = st.sidebar.slider(
    "Failed login alert threshold",
    min_value=2,
    max_value=10,
    value=3
)

uploaded_file = st.file_uploader(
    "Upload a login log CSV file",
    type=["csv"]
)

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.info("Analysing uploaded CSV file.")
else:
    df = pd.read_csv("login_logs.csv")
    st.info("Analysing the sample login dataset.")

required_columns = {
    "timestamp", "username", "ip_address", "status"
}

if not required_columns.issubset(df.columns):
    st.error("The CSV file is missing required columns.")
    st.stop()

df["timestamp"] = pd.to_datetime(
    df["timestamp"], errors="coerce"
)

df["status"] = df["status"].astype(str).str.strip().str.lower()
df["username"] = df["username"].astype(str).str.strip()
df["ip_address"] = df["ip_address"].astype(str).str.strip()

df = df.dropna(subset=["timestamp"])
df = df[df["status"].isin(["success", "failed"])]
df = df[
    (df["username"] != "")
    & (df["ip_address"] != "")
    & (df["username"].str.lower() != "nan")
    & (df["ip_address"].str.lower() != "nan")
]

if df.empty:
    st.warning("No valid login records found.")
    st.stop()

records = df.to_dict("records")
stats = calculate_statistics(records)
ip_data = analyse_ip_addresses(records)
username_data = analyse_usernames(records)
alerts = detect_suspicious_activity(records, threshold)

st.header("Login Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Logins", stats["total"])
col2.metric("Successful", stats["successful"])
col3.metric("Failed", stats["failed"])
col4.metric("Failure Rate", f"{stats['failure_rate']:.1f}%")

st.header("Login Activity")

status_counts = df["status"].value_counts()
st.bar_chart(status_counts)

st.subheader("Login Attempts Over Time")

timeline = (
    df.set_index("timestamp")
    .resample("5min")
    .size()
)

st.line_chart(timeline)

st.header("IP Address Analysis")

ip_table = pd.DataFrame.from_dict(
    ip_data, orient="index"
).reset_index()

ip_table = ip_table.rename(
    columns={"index": "IP Address"}
)

st.dataframe(ip_table, use_container_width=True)

st.subheader("Failed Logins by IP")

failed_by_ip = (
    ip_table.set_index("IP Address")["failed"]
)

st.bar_chart(failed_by_ip)

st.header("Most Targeted Usernames")

if username_data:
    username_table = pd.DataFrame(
        username_data.most_common(),
        columns=["Username", "Failed Attempts"]
    )
    st.dataframe(username_table, use_container_width=True)
else:
    st.success("No failed login attempts found.")

st.header("Security Alerts")

if alerts:
    st.warning(
        f"{len(alerts)} IP address(es) triggered security alerts."
    )

    alert_table = pd.DataFrame(alerts)
    st.dataframe(alert_table, use_container_width=True)

    csv_report = alert_table.to_csv(index=False)

    st.download_button(
        "Download Security Report",
        data=csv_report,
        file_name="security_report.csv",
        mime="text/csv"
    )
else:
    st.success("No alerts triggered by the current detection rule.")

st.header("Raw Login Records")
st.dataframe(df, use_container_width=True)

st.caption(
    "Educational cybersecurity analysis using simulated data. "
    "Alerts indicate patterns worth investigating, not confirmed attacks."
)
