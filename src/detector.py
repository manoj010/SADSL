from collections import defaultdict

def detect_suspicious_activity(logs: list, rules: dict) -> list:
    suspicious = []

    failed_login_count = defaultdict(int)

    failed_rule = rules.get("FAILED_LOGIN_THRESHOLD", {})
    restricted_rule = rules.get("RESTRICTED_URLS", {})

    for log in logs:
        ip = log["ip"]
        action = log["action"]
        status = log["status"].upper()

        if failed_rule.get("enabled") and action == "LOGIN" and status == "FAILED":
            failed_login_count[ip] += 1

            if failed_login_count[ip] > failed_rule.get("max_attempts", 3):
                suspicious.append({
                    **log,
                    "rule": "FAILED_LOGIN_THRESHOLD",
                    "severity": failed_rule.get("severity", "Low")
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
