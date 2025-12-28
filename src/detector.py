from collections import defaultdict

def detect_suspicious_activity(logs: list) -> list:
    """
    Applies basic detection rules and returns suspicious log entries.
    """

    suspicious = []

    failed_login_count = defaultdict(int)

    restricted_keywords = ["/admin", "/config"]

    for log in logs:
        ip = log["ip"]
        action = log["action"]
        status = log["status"].upper()

        if action == "LOGIN" and status == "FAILED":
            failed_login_count[ip] += 1

            if failed_login_count[ip] > 3:
                suspicious.append({
                    **log,
                    "rule": "FAILED_LOGIN_THRESHOLD"
                })

        for keyword in restricted_keywords:
            if keyword in action.lower():
                suspicious.append({
                    **log,
                    "rule": "RESTRICTED_URL_ACCESS"
                })
                break

    return suspicious
