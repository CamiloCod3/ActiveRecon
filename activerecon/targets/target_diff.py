from .target_inventory import inventory_target_key
from .parser import parse_target


def _spec_from_inventory_item(item):
    raw = item.get("raw") or item.get("host") or ""
    target_spec = parse_target(raw)
    target_spec.host = str(item.get("host") or target_spec.host).lower()
    target_spec.scheme = item.get("scheme")
    target_spec.port = item.get("port")
    target_spec.path = item.get("path") or ""
    return target_spec


def _target_map(inventory):
    targets = {}
    for item in inventory.get("targets", []):
        if not isinstance(item, dict):
            continue
        target_spec = _spec_from_inventory_item(item)
        targets[inventory_target_key(target_spec)] = item
    return targets


def diff_inventories(previous, current):
    previous_targets = _target_map(previous or {})
    current_targets = _target_map(current or {})

    previous_keys = set(previous_targets)
    current_keys = set(current_targets)

    added = [current_targets[key] for key in sorted(current_keys - previous_keys)]
    removed = [previous_targets[key] for key in sorted(previous_keys - current_keys)]
    unchanged = [current_targets[key] for key in sorted(current_keys & previous_keys)]

    return {
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
    }
