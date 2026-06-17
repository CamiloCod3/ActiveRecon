import json
from pathlib import Path


OBJECT_TARGET_FIELDS = ("target", "url", "host", "domain", "uri")


def _target_from_object(value):
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return None
    for field in OBJECT_TARGET_FIELDS:
        candidate = value.get(field)
        if candidate:
            return str(candidate)
    return None


def _targets_from_values(values):
    targets = []
    for value in values or []:
        target = _target_from_object(value)
        if target:
            targets.append(target)
    return targets


def _load_txt(path):
    targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            targets.append(line)
    return targets


def _load_json(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return _targets_from_values(data)
    if isinstance(data, dict):
        if isinstance(data.get("targets"), list):
            return _targets_from_values(data["targets"])
        target = _target_from_object(data)
        return [target] if target else []
    return []


def _load_jsonl(path):
    targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        value = json.loads(line)
        target = _target_from_object(value)
        if target:
            targets.append(target)
    return targets


def load_targets(input_file):
    path = Path(input_file)
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _load_json(path)
    if suffix == ".jsonl":
        return _load_jsonl(path)
    return _load_txt(path)
