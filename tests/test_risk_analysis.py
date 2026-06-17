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
