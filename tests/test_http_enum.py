import requests

from activerecon.modules.http_enum import analyze_http


class Response:
    status_code = 200
    url = "https://example.com:443/login"
    history = []
    headers = {
        "Server": "test",
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
    }
    text = "<html><head><title>Example App</title></head></html>"


def test_analyze_http_uses_discovered_ports_and_schemes(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append((url, timeout))
        return Response()

    monkeypatch.setattr(requests, "get", fake_get)

    results = analyze_http(
        "example.com",
        {"http_timeout": 2},
        [
            {"portid": "80", "service": "http"},
            {"portid": "443", "service": "https"},
            {"portid": "8443", "service": "ssl/http"},
        ],
    )

    assert calls == [
        ("http://example.com:80", 2),
        ("https://example.com:443", 2),
        ("https://example.com:8443", 2),
    ]
    assert [item["status"] for item in results] == [200, 200, 200]
    assert results[1]["title"] == "Example App"
    assert results[1]["final_url"] == "https://example.com:443/login"
    assert results[1]["security_headers"]["strict-transport-security"] == "max-age=31536000"
    assert "content-security-policy" in results[1]["missing_security_headers"]
    assert "server:test" in results[1]["technology_hints"]


def test_analyze_http_defaults_timeout_and_records_errors(monkeypatch):
    def fake_get(url, timeout):
        assert timeout == 5
        raise requests.Timeout("timed out")

    monkeypatch.setattr(requests, "get", fake_get)

    results = analyze_http("example.com", {}, ["8080"])

    assert results[0]["url"] == "http://example.com:8080"
    assert "timed out" in results[0]["error"]
