from activerecon.targets.parser import parse_target


def test_parse_target_splits_url_parts():
    target = parse_target("https://example.com:8443/admin")

    assert target.raw == "https://example.com:8443/admin"
    assert target.host == "example.com"
    assert target.scheme == "https"
    assert target.port == 8443
    assert target.path == "/admin"
    assert not target.is_ip


def test_parse_target_marks_ip_private_and_loopback():
    target = parse_target("127.0.0.1")

    assert target.host == "127.0.0.1"
    assert target.is_ip
    assert target.is_private
    assert target.is_loopback


def test_parse_target_marks_localhost_as_loopback_foundation():
    target = parse_target("localhost:3000")

    assert target.host == "localhost"
    assert target.port == 3000
    assert not target.is_ip
    assert target.is_private
    assert target.is_loopback
