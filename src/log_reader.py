def read_logs(file_path: str) -> list:

    logs = []

    with open(file_path, "r") as file:
        for line_no, line in enumerate(file, start=1):
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            parts = [part.strip() for part in line.split("|")]

            if len(parts) != 4:
                print(f"[WARNING] Malformed line {line_no}: {line}")
                continue

            timestamp, ip, action, status = parts

            log_entry = {
                "line_no": line_no,
                "timestamp": timestamp,
                "ip": ip,
                "action": action,
                "status": status
            }

            logs.append(log_entry)

    return logs