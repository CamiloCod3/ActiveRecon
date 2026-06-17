import json

from activerecon.modules.json_report import build_json_payload, generate_json_report


def test_build_json_payload_wraps_results_with_schema():
    payload = build_json_payload("example.com", {"Nmap Scan": {"ports": []}}, "2026-06-17T09:08:07Z")

    assert payload["schema_version"] == "1.1"
    assert payload["generated_at"] == "2026-06-17T09:08:07Z"
    assert payload["target"] == "example.com"
    assert payload["metadata"]["tool"] == "ActiveRecon"
    assert payload["metadata"]["authorized_use_notice"] is True
    assert payload["summary"]["total_ports_listed"] == 0
    assert payload["results"]["Nmap Scan"]["ports"] == []


def test_build_json_payload_adds_summary_metadata_alias_and_endpoint_categories():
    results = {
        "Nmap Scan": {
            "status": {"state": "up"},
            "host": "127.0.0.1",
            "ports": [
                {"portid": "80", "state": "open"},
                {"portid": "25", "state": "filtered"},
            ],
        },
        "HTTP Analysis": [
            {
                "url": "http://127.0.0.1:80",
                "status": 200,
                "missing_security_headers": [
                    "strict-transport-security",
                    "content-security-policy",
                ],
            }
        ],
        "TLS Analysis": [{"host": "127.0.0.1", "port": 443}],
        "DNS Analysis": {"A": ["127.0.0.1"], "MX": [], "TXT": []},
        "Endpoint Discovery": [
            {
                "base_url": "http://127.0.0.1",
                "endpoints": [
                    {"path": "/api", "source": "well-known"},
                    {"path": "/api", "source": "javascript"},
                    {"path": "/login", "source": "html:href"},
                    {"path": "/app.js", "source": "html:script-src"},
                    {"path": "/robots.txt", "source": "well-known"},
                    {"path": "/#/jobs", "source": "response-header:X-Recruiting"},
                    {"path": "/socket.io/?EIO=4", "source": "javascript"},
                ],
            }
        ],
        "Attention": [
            {
                "severity": "info",
                "category": "endpoint",
                "message": "API-like endpoint discovered; follow-up recommended",
                "evidence": "http://127.0.0.1/api",
            }
        ],
    }

    payload = build_json_payload(
        "127.0.0.1",
        results,
        "2026-06-17T09:08:07Z",
        scan_profile="web",
    )

    assert payload["metadata"]["scan_profile"] == "web"
    assert "local or private" in payload["metadata"]["scan_context"]
    assert payload["summary"] == {
        "host_status": "up",
        "total_ports_listed": 2,
        "open_ports": 1,
        "http_services": 1,
        "tls_results": 1,
        "dns_records": 1,
        "interesting_signals": 1,
        "endpoint_count": 6,
    }
    assert "Attention" in payload["results"]
    assert "Interesting Signals" in payload["results"]
    assert payload["results"]["Interesting Signals"] == payload["results"]["Attention"]
    assert payload["results"]["HTTP Analysis"][0]["missing_security_headers"] == ["content-security-policy"]

    endpoint_group = payload["results"]["Endpoint Discovery"][0]
    assert len(endpoint_group["endpoints"]) == 7
    assert endpoint_group["summary"] == {
        "endpoint_count": 6,
        "api_like": 1,
        "frontend_routes": 2,
        "static_assets": 1,
        "well_known": 1,
        "header_discovered": 1,
        "realtime_services": 1,
    }
    assert endpoint_group["categories"]["api_like"][0]["path"] == "/api"
    assert len(endpoint_group["categories"]["api_like"]) == 2
    assert endpoint_group["categories"]["frontend_routes"][0]["path"] == "/login"
    assert endpoint_group["categories"]["static_assets"][0]["path"] == "/app.js"
    assert endpoint_group["categories"]["well_known"][0]["path"] == "/robots.txt"
    assert endpoint_group["categories"]["header_discovered"][0]["path"] == "/#/jobs"
    assert endpoint_group["categories"]["realtime_services"][0]["path"] == "/socket.io/?EIO=4"


def test_generate_json_report_writes_file(tmp_path):
    output = tmp_path / "reports" / "example.json"

    generate_json_report("example.com", {"Attention": []}, str(output), "2026-06-17T09:08:07Z", scan_profile="fast")

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["target"] == "example.com"
    assert data["metadata"]["scan_profile"] == "fast"
    assert data["results"]["Attention"] == []
    assert data["results"]["Interesting Signals"] == []
