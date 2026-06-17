import ipaddress
from pathlib import Path

from ..targets.parser import parse_target


def _read_scope_file(scope_file):
    entries = []
    for line in Path(scope_file).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


def _domain_matches(target_host, entry):
    entry_host = parse_target(entry).host
    return target_host == entry_host or target_host.endswith(f".{entry_host}")


def _ip_matches(target_host, entry):
    try:
        target_ip = ipaddress.ip_address(target_host)
    except ValueError:
        return False

    try:
        return target_ip in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        try:
            return target_ip == ipaddress.ip_address(entry)
        except ValueError:
            return False


class ScopePolicy:
    def __init__(self, entries):
        self.entries = list(entries or [])

    @classmethod
    def from_file(cls, scope_file):
        return cls(_read_scope_file(scope_file))

    def allows(self, target):
        target_host = parse_target(target).host
        return any(
            _ip_matches(target_host, entry) or _domain_matches(target_host, entry)
            for entry in self.entries
        )
