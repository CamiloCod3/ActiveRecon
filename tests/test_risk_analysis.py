from datetime import datetime

from activerecon.modules.risk_analysis import generate_attention_findings


def test_generate_attention_findings_reports_http_headers_and_sensitive_ports():
    results = {
        "Nmap Scan": {
            "ports": [
                {"portid": "23", "service": "telnet", "state": "open"},
                {"portid": "443", "service": "https", "state": "open"},
            ],
        },
        "HTTP Analysis": [{
            "url": "https://example.com",
            "missing_security_headers": ["content-security-policy"],
            "redirect_chain": ["http://example.com"],
        }],
        "DNS Analysis": {"errors": {"MX": "missing"}},
    }

    findings = generate_attention_findings(results)
    messages = [item["message"] for item in findings]

    assert "Sensitive remote access service exposed on port 23" in messages
    assert "Missing Content-Security-Policy header" in messages
    assert "HTTP redirects observed" in messages
    assert "DNS MX lookup returned no usable result" in messages


def test_generate_attention_findings_only_reports_open_http_ports():
    results = {
        "Nmap Scan": {
            "ports": [
                {"portid": "3000", "service": "ppp", "state": "open"},
                {"portid": "8080", "service": "http", "state": "closed"},
                {"portid": "8443", "service": "https", "state": "filtered"},
                {"portid": "23", "service": "telnet", "state": "closed"},
            ],
        },
    }

    findings = generate_attention_findings(results)
    messages = [item["message"] for item in findings]

    assert "HTTP service detected on port 3000" in messages
    assert "HTTP service detected on port 8080" not in messages
    assert "HTTP service detected on port 8443" not in messages
    assert "Sensitive remote access service exposed on port 23" not in messages


def test_generate_attention_findings_reports_smb_rdp_and_rpc_exposure():
    results = {
        "Nmap Scan": {
            "ports": [
                {"portid": "445", "service": "microsoft-ds", "state": "open"},
                {"portid": "3389", "service": "ms-wbt-server", "state": "open"},
                {"portid": "135", "service": "msrpc", "state": "open"},
            ],
        },
    }

    findings = generate_attention_findings(results)
    by_message = {item["message"]: item for item in findings}

    assert by_message["SMB service exposed on port 445"]["severity"] == "medium"
    assert by_message["Sensitive remote access service exposed on port 3389"]["severity"] == "medium"
    assert by_message["RPC endpoint mapper observed on port 135"]["severity"] == "info"


def test_generate_attention_findings_reports_hsts_only_for_https():
    results = {
        "HTTP Analysis": [
            {
                "url": "http://example.com",
                "missing_security_headers": [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                ],
            },
            {
                "url": "https://secure.example.com",
                "missing_security_headers": [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                ],
            },
        ],
    }

    findings = generate_attention_findings(results)
    messages = [item["message"] for item in findings]

    assert messages.count("Missing HSTS header") == 1
    assert messages.count("Missing Content-Security-Policy header") == 2
    assert messages.count("Missing X-Frame-Options header") == 2
    assert messages.count("Missing X-Content-Type-Options header") == 2


def test_generate_attention_findings_reports_cors_and_header_paths_as_info():
    results = {
        "HTTP Analysis": [{
            "url": "http://example.com",
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "X-Recruiting": "/#/jobs",
                "X-Powered-By": "Express",
                "X-Plain": "no path here",
            },
        }],
    }

    findings = generate_attention_findings(results)
    cors_finding = next(item for item in findings if item["category"] == "cors")
    endpoint_finding = next(item for item in findings if item["category"] == "endpoint")
    technology_finding = next(item for item in findings if item["category"] == "technology")

    assert cors_finding["severity"] == "info"
    assert cors_finding["message"] == "Wildcard CORS header observed"
    assert cors_finding["evidence"] == "http://example.com"
    assert endpoint_finding["severity"] == "info"
    assert endpoint_finding["message"] == "Interesting path found in response header X-Recruiting"
    assert endpoint_finding["evidence"] == "/#/jobs"
    assert technology_finding["severity"] == "info"
    assert technology_finding["message"] == "X-Powered-By header exposed"
    assert technology_finding["evidence"] == "Express - http://example.com"
    assert all(item.get("evidence") != "no path here" for item in findings)


def test_generate_attention_findings_reports_endpoint_discovery_signals():
    results = {
        "Endpoint Discovery": [{
            "base_url": "http://example.com",
            "endpoints": [
                {"path": "/api", "source": "well-known", "status_code": 200},
                {"path": "/robots.txt", "source": "well-known", "status_code": 200},
                {"path": "/hidden", "source": "robots.txt"},
                {"path": "/#/jobs", "source": "response-header:X-Recruiting"},
                {"path": "/api/orders", "source": "javascript"},
                {"path": "/admin", "source": "well-known", "status_code": 403},
                {"path": "/ftp", "source": "well-known", "status_code": 200},
            ],
        }],
    }

    findings = generate_attention_findings(results)
    messages = [item["message"] for item in findings]

    assert "API-like endpoint discovered" in messages
    assert "robots.txt found" in messages
    assert "robots.txt contains Disallow paths" in messages
    assert "Interesting endpoint from response header" in messages
    assert "JavaScript exposes API-like paths" in messages
    assert "Possible admin/debug/docs route discovered" in messages
    assert "/ftp endpoint discovered" in messages


def test_generate_attention_findings_reports_expired_tls_certificates():
    results = {
        "TLS Analysis": [{
            "url": "https://example.com",
            "not_after": "Jan  1 00:00:00 2020 GMT",
        }]
    }

    findings = generate_attention_findings(results, now=datetime(2026, 1, 1))

    assert findings[0]["severity"] == "high"
    assert findings[0]["message"] == "TLS certificate is expired"
