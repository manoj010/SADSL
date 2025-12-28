from collections import defaultdict
from utils import parse_timestamp
from datetime import timedelta


def detect_suspicious_activity(logs: list, rules: dict) -> list:
    suspicious = []

    failed_count_rule = rules.get("FAILED_LOGIN_THRESHOLD", {})
    failed_time_rule = rules.get("FAILED_LOGIN_TIME_WINDOW", {})
    restricted_rule = rules.get("RESTRICTED_URLS", {})

    failed_login_count = defaultdict(int)
    failed_login_times = defaultdict(list)

    for log in logs:
        ip = log["ip"]
        action = log["action"]
        status = log["status"].upper()
        timestamp = parse_timestamp(log["timestamp"])

        if (
            failed_count_rule.get("enabled")
            and action == "LOGIN"
            and status == "FAILED"
        ):
            failed_login_count[ip] += 1

            if failed_login_count[ip] > failed_count_rule.get("max_attempts", 3):
                suspicious.append({
                    **log,
                    "rule": "FAILED_LOGIN_THRESHOLD",
                    "severity": failed_count_rule.get("severity", "Low")
                })

        if (
            failed_time_rule.get("enabled")
            and action == "LOGIN"
            and status == "FAILED"
        ):
            failed_login_times[ip].append(timestamp)

            window = timedelta(
                minutes=failed_time_rule.get("window_minutes", 5)
            )

            failed_login_times[ip] = [
                t for t in failed_login_times[ip]
                if timestamp - t <= window
            ]

            if len(failed_login_times[ip]) > failed_time_rule.get("max_attempts", 3):
                suspicious.append({
                    **log,
                    "rule": "FAILED_LOGIN_TIME_WINDOW",
                    "severity": failed_time_rule.get("severity", "Low")
                })

        if restricted_rule.get("enabled"):
            for url in restricted_rule.get("urls", []):
                if url in action.lower():
                    suspicious.append({
                        **log,
                        "rule": "RESTRICTED_URL_ACCESS",
                        "severity": restricted_rule.get("severity", "Low")
                    })
                    break

    return suspicious
