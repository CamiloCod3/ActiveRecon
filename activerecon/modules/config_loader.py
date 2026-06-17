from pathlib import Path

import yaml


def get_config_path():
    return Path(__file__).resolve().parent / "config" / "config.yaml"


def load_config():
    """
    Loads the YAML configuration file and returns it as a dict.
    """
    config_path = get_config_path()

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
