from activerecon.modules.scope_guard import is_target_in_scope


def test_scope_guard_allows_exact_domain_and_subdomain(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n", encoding="utf-8")

    assert is_target_in_scope("example.com", str(scope))
    assert is_target_in_scope("api.example.com", str(scope))


def test_scope_guard_allows_ip_cidr(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("192.0.2.0/24\n", encoding="utf-8")

    assert is_target_in_scope("192.0.2.10", str(scope))
    assert not is_target_in_scope("198.51.100.10", str(scope))


def test_scope_guard_ignores_comments_and_blank_lines(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("\n# comment\nallowed.example.com # inline\n", encoding="utf-8")

    assert is_target_in_scope("allowed.example.com", str(scope))
    assert not is_target_in_scope("example.com", str(scope))
