import ipaddress
from pathlib import Path
from urllib.parse import urlparse


def _clean_target(value):
    value = value.strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value
    return host.strip().rstrip(".").lower()


def _read_scope(scope_file):
    entries = []
    for line in Path(scope_file).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


def _domain_matches(target, entry):
    entry = _clean_target(entry)
    return target == entry or target.endswith(f".{entry}")


def _ip_matches(target, entry):
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        return False

    try:
        return target_ip in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        try:
            return target_ip == ipaddress.ip_address(entry)
        except ValueError:
            return False


def is_target_in_scope(target, scope_file):
    normalized_target = _clean_target(target)
    return any(
        _ip_matches(normalized_target, entry) or _domain_matches(normalized_target, entry)
        for entry in _read_scope(scope_file)
    )
