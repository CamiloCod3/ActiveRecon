import json

from activerecon.policies.scope_policy import ScopePolicy


def _write_json_scope(path, allowed=None, denied=None):
    path.write_text(
        json.dumps({
            "schema_version": "1.0",
            "program": "Example Program",
            "platform": "test",
            "allowed": allowed or {},
            "denied": denied or {},
            "rules": {"notes": "test rules"},
        }),
        encoding="utf-8",
    )
    return path


def test_scope_policy_allows_domain_subdomain_ip_and_cidr():
    policy = ScopePolicy(["example.com", "192.0.2.0/24", "198.51.100.10"])

    assert policy.allows("example.com")
    assert policy.allows("api.example.com")
    assert policy.allows("192.0.2.5")
    assert policy.allows("198.51.100.10")
    assert not policy.allows("other.example.net")
    assert not policy.allows("203.0.113.10")


def test_scope_policy_loads_scope_files_with_comments(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("\n# comment\nallowed.example.com # inline\n", encoding="utf-8")

    policy = ScopePolicy.from_file(scope)

    assert policy.allows("allowed.example.com")
    assert not policy.allows("example.com")


def test_json_scope_allows_exact_domain(tmp_path):
    scope = _write_json_scope(tmp_path / "scope.json", allowed={"domains": ["api.example.com"]})

    evaluation = ScopePolicy.from_file(scope).evaluate("api.example.com")

    assert evaluation["allowed"] is True
    assert evaluation["matched_rule"] == "api.example.com"
    assert evaluation["matched_section"] == "allowed.domains"
    assert evaluation["program"] == "Example Program"
    assert evaluation["rules"] == {"notes": "test rules"}


def test_json_scope_allows_wildcard(tmp_path):
    scope = _write_json_scope(tmp_path / "scope.json", allowed={"wildcards": ["*.example.com"]})

    assert ScopePolicy.from_file(scope).allows("api.example.com")
    assert not ScopePolicy.from_file(scope).allows("example.com")


def test_json_scope_denied_domain_overrides_allowed_wildcard(tmp_path):
    scope = _write_json_scope(
        tmp_path / "scope.json",
        allowed={"wildcards": ["*.example.com"]},
        denied={"domains": ["admin.example.com"]},
    )

    evaluation = ScopePolicy.from_file(scope).evaluate("admin.example.com")

    assert evaluation["allowed"] is False
    assert evaluation["matched_rule"] == "admin.example.com"
    assert evaluation["matched_section"] == "denied.domains"
    assert "denied" in evaluation["reason"]


def test_json_scope_denied_wildcard_works(tmp_path):
    scope = _write_json_scope(
        tmp_path / "scope.json",
        allowed={"wildcards": ["*.example.com"]},
        denied={"wildcards": ["*.admin.example.com"]},
    )

    assert not ScopePolicy.from_file(scope).allows("panel.admin.example.com")
    assert ScopePolicy.from_file(scope).allows("api.example.com")


def test_json_scope_url_allow_works(tmp_path):
    scope = _write_json_scope(
        tmp_path / "scope.json",
        allowed={"urls": ["https://api.example.com/login"]},
    )

    policy = ScopePolicy.from_file(scope)

    assert policy.allows("https://api.example.com/login")
    assert not policy.allows("https://api.example.com/logout")
    assert not policy.allows("http://api.example.com/login")


def test_json_scope_ip_and_cidr_allow_works(tmp_path):
    scope = _write_json_scope(
        tmp_path / "scope.json",
        allowed={"ips": ["127.0.0.1"], "cidrs": ["192.0.2.0/24"]},
    )

    policy = ScopePolicy.from_file(scope)

    assert policy.allows("127.0.0.1")
    assert policy.allows("192.0.2.42")
    assert not policy.allows("198.51.100.10")


def test_json_scope_evaluate_returns_denied_no_match_details(tmp_path):
    scope = _write_json_scope(tmp_path / "scope.json", allowed={"domains": ["example.com"]})

    evaluation = ScopePolicy.from_file(scope).evaluate("not-example.test")

    assert evaluation == {
        "allowed": False,
        "reason": "No allowed scope rule matched target: not-example.test",
        "matched_rule": "",
        "matched_section": "",
        "program": "Example Program",
        "rules": {"notes": "test rules"},
    }
