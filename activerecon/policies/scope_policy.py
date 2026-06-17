import ipaddress
import json
from fnmatch import fnmatchcase
from pathlib import Path

from ..targets.parser import parse_target


SCOPE_CATEGORIES = ("domains", "wildcards", "urls", "ips", "cidrs")


def _read_text_scope(scope_file):
    entries = []
    for line in Path(scope_file).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


def _read_json_scope(scope_file):
    return json.loads(Path(scope_file).read_text(encoding="utf-8"))


def _is_json_scope(scope_file):
    path = Path(scope_file)
    if path.suffix.lower() == ".json":
        return True
    text = path.read_text(encoding="utf-8").lstrip()
    return text.startswith("{")


def _domain_matches_text_scope(target_host, entry):
    entry_host = parse_target(entry).host
    return target_host == entry_host or target_host.endswith(f".{entry_host}")


def _domain_matches_exact(target_host, entry):
    return target_host == parse_target(entry).host


def _wildcard_matches(target_host, entry):
    pattern = str(entry or "").strip().lower()
    if not pattern:
        return False
    if "://" in pattern:
        pattern = parse_target(pattern).host
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return target_host != suffix and target_host.endswith(f".{suffix}")
    return fnmatchcase(target_host, pattern)


def _ip_matches(target_host, entry):
    try:
        target_ip = ipaddress.ip_address(target_host)
    except ValueError:
        return False

    try:
        return target_ip == ipaddress.ip_address(entry)
    except ValueError:
        return False


def _cidr_matches(target_host, entry):
    try:
        target_ip = ipaddress.ip_address(target_host)
        return target_ip in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False


def _text_entry_matches(target_host, entry):
    return (
        _ip_matches(target_host, entry)
        or _cidr_matches(target_host, entry)
        or _domain_matches_text_scope(target_host, entry)
    )


def _normalized_path(path):
    return "" if path in ("", "/") else str(path or "").rstrip("/")


def _url_matches(target_spec, entry):
    entry_spec = parse_target(entry)
    if not entry_spec.scheme:
        return False
    if target_spec.scheme != entry_spec.scheme:
        return False
    if target_spec.host != entry_spec.host:
        return False
    if target_spec.port != entry_spec.port:
        return False
    return _normalized_path(target_spec.path) == _normalized_path(entry_spec.path)


def _empty_evaluation(target, program="", rules=None, allowed=False, reason=""):
    return {
        "allowed": allowed,
        "reason": reason or f"No scope rule matched target: {target}",
        "matched_rule": "",
        "matched_section": "",
        "program": program or "",
        "rules": rules or {},
    }


class ScopePolicy:
    def __init__(self, entries=None, scope_data=None):
        self.entries = list(entries or [])
        self.scope_data = scope_data or {}
        self.program = self.scope_data.get("program", "")
        self.rules = self.scope_data.get("rules", {})

    @classmethod
    def from_file(cls, scope_file):
        if _is_json_scope(scope_file):
            return cls(scope_data=_read_json_scope(scope_file))
        return cls(entries=_read_text_scope(scope_file))

    def _json_section_entries(self, section, category):
        values = self.scope_data.get(section, {}).get(category, [])
        return values if isinstance(values, list) else []

    def _category_matches(self, category, target_spec, rule):
        if category == "domains":
            return _domain_matches_exact(target_spec.host, rule)
        if category == "wildcards":
            return _wildcard_matches(target_spec.host, rule)
        if category == "urls":
            return _url_matches(target_spec, rule)
        if category == "ips":
            return _ip_matches(target_spec.host, rule)
        if category == "cidrs":
            return _cidr_matches(target_spec.host, rule)
        return False

    def _evaluate_json_section(self, section, target_spec):
        for category in SCOPE_CATEGORIES:
            for rule in self._json_section_entries(section, category):
                if self._category_matches(category, target_spec, rule):
                    return {
                        "matched_rule": str(rule),
                        "matched_section": f"{section}.{category}",
                    }
        return None

    def _evaluate_json(self, target):
        target_spec = parse_target(target)
        denied_match = self._evaluate_json_section("denied", target_spec)
        if denied_match:
            return {
                "allowed": False,
                "reason": (
                    f"Target denied by {denied_match['matched_section']} "
                    f"rule: {denied_match['matched_rule']}"
                ),
                "matched_rule": denied_match["matched_rule"],
                "matched_section": denied_match["matched_section"],
                "program": self.program,
                "rules": self.rules,
            }

        allowed_match = self._evaluate_json_section("allowed", target_spec)
        if allowed_match:
            return {
                "allowed": True,
                "reason": (
                    f"Target allowed by {allowed_match['matched_section']} "
                    f"rule: {allowed_match['matched_rule']}"
                ),
                "matched_rule": allowed_match["matched_rule"],
                "matched_section": allowed_match["matched_section"],
                "program": self.program,
                "rules": self.rules,
            }

        return _empty_evaluation(
            target,
            self.program,
            self.rules,
            allowed=False,
            reason=f"No allowed scope rule matched target: {target}",
        )

    def _evaluate_text(self, target):
        target_host = parse_target(target).host
        for entry in self.entries:
            if _text_entry_matches(target_host, entry):
                return {
                    "allowed": True,
                    "reason": f"Target allowed by text scope entry: {entry}",
                    "matched_rule": entry,
                    "matched_section": "allowed.text",
                    "program": "",
                    "rules": {},
                }
        return _empty_evaluation(target, allowed=False)

    def evaluate(self, target):
        if self.scope_data:
            return self._evaluate_json(target)
        return self._evaluate_text(target)

    def allows(self, target):
        return bool(self.evaluate(target)["allowed"])
