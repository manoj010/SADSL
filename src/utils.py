import json

def load_rules(config_path: str) -> dict:
    with open(config_path, "r") as file:
        return json.load(file)