from activerecon.policies.scope_policy import ScopePolicy


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
