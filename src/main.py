from log_reader import read_logs
from detector import detect_suspicious_activity


def main():
    print("Suspicious Activity Detector from System Logs (SADSL)")
    print("Starting log analysis...\n")

    log_file = "logs/login.log"
    logs = read_logs(log_file)

    suspicious_logs = detect_suspicious_activity(logs)

    print("Suspicious Activity Detected:\n")
    for entry in suspicious_logs:
        print(
            f"Line {entry['line_no']} | IP {entry['ip']} | "
            f"Rule: {entry['rule']} | Action: {entry['action']} | Status: {entry['status']}"
        )

    suspicious_ips = set()
    total_failed_attempts = 0

    for log in logs:
        if log["status"].upper() == "FAILED":
            total_failed_attempts += 1

    for entry in suspicious_logs:
        suspicious_ips.add(entry["ip"])

    print("\nSummary:")
    print(f"Total suspicious IPs: {len(suspicious_ips)}")
    print(f"Total failed login attempts: {total_failed_attempts}")


if __name__ == "__main__":
    main()
