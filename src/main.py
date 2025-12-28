from log_reader import read_logs
from detector import detect_suspicious_activity
from utils import load_rules
from db import create_tables, insert_suspicious_event

def main():
    print("Suspicious Activity Detector from System Logs (SADSL)")
    print("Starting log analysis...\n")

    log_file = "logs/login.log"
    rules_file = "config/rules.json"

    logs = read_logs(log_file)
    rules = load_rules(rules_file)

    create_tables()

    suspicious_logs = detect_suspicious_activity(logs, rules)

    print("Suspicious Activity Detected:\n")
    for entry in suspicious_logs:
        print(
            f"Line {entry['line_no']} | IP {entry['ip']} | "
            f"Rule: {entry['rule']} | Severity: {entry['severity']} | "
            f"Action: {entry['action']} | Status: {entry['status']}"
        )

        insert_suspicious_event(entry)

    print("\nSummary:")
    suspicious_ips = {entry["ip"] for entry in suspicious_logs}
    total_failed_attempts = sum(
        1 for log in logs if log["status"].upper() == "FAILED"
    )

    print(f"Total suspicious IPs: {len(suspicious_ips)}")
    print(f"Total failed login attempts: {total_failed_attempts}")


if __name__ == "__main__":
    main()
