from collections import Counter
from datetime import datetime
import json

def load_rules(config_path: str) -> dict:
    with open(config_path, "r") as file:
        return json.load(file)

def parse_timestamp(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

def get_most_targeted_urls(logs: list, limit=10):
    urls = []

    for log in logs:
        action = log["action"].lower()
        if action.startswith("access"):
            urls.append(action)

    counter = Counter(urls)
    return counter.most_common(limit)