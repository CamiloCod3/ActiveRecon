import json
from datetime import datetime, timezone
from pathlib import Path

from .parser import parse_target


INVENTORY_SCHEMA_VERSION = "1.0"
DEFAULT_SOURCE = "manual"


def _utc_timestamp():
    return datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None).isoformat() + "Z"


def _normalized_path(path):
    if path in ("", "/"):
        return ""
    return str(path or "").rstrip("/")


def inventory_target_key(target_spec):
    scheme = target_spec.scheme or ""
    port = "" if target_spec.port is None else str(target_spec.port)
    return "|".join([scheme, target_spec.host, port, _normalized_path(target_spec.path)])


def target_spec_to_dict(target_spec):
    return {
        "raw": target_spec.raw,
        "host": target_spec.host,
        "scheme": target_spec.scheme,
        "port": target_spec.port,
        "path": target_spec.path,
        "is_ip": target_spec.is_ip,
        "is_private": target_spec.is_private,
        "is_loopback": target_spec.is_loopback,
    }


def build_inventory(targets, source=None, generated_at=None):
    seen = set()
    normalized_targets = []

    for raw_target in targets or []:
        if not str(raw_target or "").strip():
            continue
        target_spec = parse_target(raw_target)
        key = inventory_target_key(target_spec)
        if key in seen:
            continue
        seen.add(key)
        normalized_targets.append(target_spec_to_dict(target_spec))

    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "generated_at": generated_at or _utc_timestamp(),
        "source": source or DEFAULT_SOURCE,
        "targets": normalized_targets,
    }


def save_inventory(inventory, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2, sort_keys=True)
        f.write("\n")


def load_inventory(input_file):
    input_path = Path(input_file)
    with input_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def export_scope_file(inventory, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    seen_hosts = set()
    hosts = []

    for item in inventory.get("targets", []):
        host = str(item.get("host", "")).strip().lower()
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            hosts.append(host)

    with output_path.open("w", encoding="utf-8") as f:
        for host in hosts:
            f.write(f"{host}\n")
