 
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# ==========================================
# CYBERSECURITY LOG ANALYSER
# ==========================================

LOG_FILE = "login_logs.csv"
REPORT_FILE = "security_report.csv"
FAILED_LOGIN_THRESHOLD = 3

REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "ip_address",
    "status"
}


def load_logs(filename):
    """Read and validate login records from a CSV file."""
    records = []
    skipped_rows = 0

    try:
        with open(filename, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                print("Error: The log file is empty.")
                return []

            if not REQUIRED_COLUMNS.issubset(set(reader.fieldnames)):
                print("Error: The CSV file has missing columns.")
                return []

            for row in reader:
                try:
                    timestamp = datetime.strptime(
                        row["timestamp"].strip(),
                        "%Y-%m-%d %H:%M:%S"
                    )

                    username = row["username"].strip()
                    ip_address = row["ip_address"].strip()
                    status = row["status"].strip().lower()

                    if not username or not ip_address:
                        raise ValueError("Missing login information")

                    if status not in ("success", "failed"):
                        raise ValueError("Invalid login status")

                    records.append({
                        "timestamp": timestamp,
                        "username": username,
                        "ip_address": ip_address,
                        "status": status
                    })

                except (ValueError, AttributeError, TypeError):
                    skipped_rows += 1

    except FileNotFoundError:
        print(f"Error: Could not find {filename}")
        return []

    except OSError as error:
        print(f"Error reading file: {error}")
        return []

    if skipped_rows:
        print(f"Skipped {skipped_rows} invalid record(s).")

    return records


def calculate_statistics(records):
    """Calculate overall login statistics."""
    total = len(records)

    successful = sum(
        1 for record in records
        if record["status"] == "success"
    )

    failed = total - successful

    failure_rate = (
        (failed / total) * 100 if total > 0 else 0
    )

    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "failure_rate": failure_rate
    }


def analyse_ip_addresses(records):
    """Count login attempts and failures for each IP."""
    ip_data = defaultdict(
        lambda: {"total": 0, "failed": 0, "successful": 0}
    )

    for record in records:
        ip = record["ip_address"]
        ip_data[ip]["total"] += 1

        if record["status"] == "failed":
            ip_data[ip]["failed"] += 1
        else:
            ip_data[ip]["successful"] += 1

    return dict(ip_data)


def analyse_usernames(records):
    """Count failed logins for each username."""
    return Counter(
        record["username"]
        for record in records
        if record["status"] == "failed"
    )


def detect_suspicious_activity(records, threshold):
    """Identify IP addresses with repeated failed logins."""
    failed_by_ip = defaultdict(list)

    for record in records:
        if record["status"] == "failed":
            failed_by_ip[record["ip_address"]].append(record)

    alerts = []

    for ip_address, failures in failed_by_ip.items():
        if len(failures) >= threshold:
            usernames = sorted({
                record["username"] for record in failures
            })

            alerts.append({
                "ip_address": ip_address,
                "failed_attempts": len(failures),
                "usernames": ", ".join(usernames),
                "severity": (
                    "HIGH"
                    if len(failures) >= threshold * 2
                    else "MEDIUM"
                ),
                "description": "Repeated failed login attempts"
            })

    return sorted(
        alerts,
        key=lambda alert: alert["failed_attempts"],
        reverse=True
    )


def display_dashboard(records):
    """Display login statistics and security analysis."""
    stats = calculate_statistics(records)
    ip_data = analyse_ip_addresses(records)
    username_data = analyse_usernames(records)

    alerts = detect_suspicious_activity(
        records,
        FAILED_LOGIN_THRESHOLD
    )

    print("\n" + "=" * 55)
    print("       CYBERSECURITY LOG ANALYSER")
    print("=" * 55)

    print("\nLOGIN STATISTICS")
    print("-" * 55)
    print(f"Total login attempts:      {stats['total']}")
    print(f"Successful logins:         {stats['successful']}")
    print(f"Failed logins:             {stats['failed']}")
    print(f"Failure rate:              {stats['failure_rate']:.2f}%")
    print(f"Unique IP addresses:       {len(ip_data)}")

    print("\nIP ADDRESS ANALYSIS")
    print("-" * 55)

    for ip, data in sorted(
        ip_data.items(),
        key=lambda item: item[1]["failed"],
        reverse=True
    ):
        print(
            f"{ip} | "
            f"Total: {data['total']} | "
            f"Failed: {data['failed']} | "
            f"Successful: {data['successful']}"
        )

    print("\nMOST TARGETED USERNAMES")
    print("-" * 55)

    if username_data:
        for username, failures in username_data.most_common(5):
            print(f"{username}: {failures} failed attempt(s)")
    else:
        print("No failed logins found.")

    print("\nSECURITY ALERTS")
    print("-" * 55)

    if alerts:
        for index, alert in enumerate(alerts, start=1):
            print(f"\nAlert {index}")
            print(f"Severity:       {alert['severity']}")
            print(f"IP Address:     {alert['ip_address']}")
            print(f"Failed Logins:  {alert['failed_attempts']}")
            print(f"Usernames:      {alert['usernames']}")
            print(f"Reason:         {alert['description']}")
    else:
        print("No suspicious activity detected.")

    print("\nNOTE: Alerts indicate patterns worth investigating.")
    print("They do not prove that an attack occurred.")

    return alerts


def export_report(alerts, filename):
    """Export detected security alerts to a CSV file."""
    columns = [
        "ip_address",
        "failed_attempts",
        "usernames",
        "severity",
        "description"
    ]

    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=columns)
            writer.writeheader()
            writer.writerows(alerts)

        print(f"\nReport saved to: {filename}")

    except OSError as error:
        print(f"Could not save report: {error}")


def main():
    print("Loading cybersecurity login records...")

    records = load_logs(LOG_FILE)

    if not records:
        print("No valid records available for analysis.")
        return

    alerts = display_dashboard(records)
    export_report(alerts, REPORT_FILE)

    print("\nAnalysis completed successfully.")


if __name__ == "__main__":
    main()
