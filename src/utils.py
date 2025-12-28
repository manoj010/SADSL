from datetime import datetime
import json

def load_rules(config_path: str) -> dict:
    with open(config_path, "r") as file:
        return json.load(file)

def parse_timestamp(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")