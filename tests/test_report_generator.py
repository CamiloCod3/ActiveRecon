from activerecon.modules.report_generator import generate_report


def test_generate_report_writes_nested_results(tmp_path):
    output = tmp_path / "report.md"
    results = {
        "Nmap Scan": {
            "status": {"state": "up"},
            "scan_info": {"protocol": "tcp", "numservices": "100"},
            "host": "93.184.216.34",
            "ports": [
                {
                    "portid": "25",
                    "protocol": "tcp",
                    "state": "filtered",
                    "service": "smtp",
                },
                {
                    "portid": "80",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                },
            ],
        },
        "HTTP Analysis": [{
            "url": "http://example.com:80",
            "final_url": "https://example.com/login",
            "service": "ppp",
            "status": 200,
            "title": "Example App",
            "redirect_chain": ["http://example.com:80", "https://example.com/login"],
            "missing_security_headers": ["content-security-policy"],
            "technology_hints": ["server:test"],
            "headers": {"Server": "test"},
        }],
        "TLS Analysis": [{
            "host": "example.com",
            "port": 443,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "subject": ["example.com"],
            "issuer": ["Example CA"],
            "not_before": "Jan  1 00:00:00 2026 GMT",
            "not_after": "Jan  1 00:00:00 2027 GMT",
        }],
        "DNS Analysis": {
            "A": ["192.0.2.10"],
            "MX": [],
            "TXT": [],
            "errors": {"MX": "missing"},
        },
        "Endpoint Discovery": [{
            "base_url": "http://example.com",
            "endpoints": [{
                "path": "/api",
                "source": "well-known",
                "confidence": "medium",
                "status_code": 200,
                "content_type": "application/json",
            }],
        }],
        "Attention": [{
            "severity": "low",
            "category": "http",
            "message": "Missing Content-Security-Policy header",
            "evidence": "https://example.com",
        }],
    }

    generate_report("example.com", results, str(output))

    content = output.read_text(encoding="utf-8")
    assert "# Active Recon Report" in content
    assert "## Summary" in content
    assert "- **Open Ports:** 1" in content
    assert "- **HTTP Services:** 1" in content
    assert "- **DNS Records:** 1" in content
    assert "## Port Scan Results" in content
    assert "\n## Open Ports\n" not in content
    assert "### Open Ports" in content
    assert "### Other Results" in content
    assert content.index("### Open Ports") < content.index("### Other Results")
    assert content.index("80/tcp") < content.index("25/tcp")
    assert "## HTTP Analysis" in content
    assert "http://example.com:80" in content
    assert "- **Nmap Service:** ppp" in content
    assert "- **Detected HTTP:** yes" in content
    assert "- **Status:** 200" in content
    assert "- **Title:** Example App" in content
    assert "- **Final URL:** https://example.com/login" in content
    assert "- **Redirect Chain:**" in content
    assert "  - `https://example.com/login`" in content
    assert "- **Missing Security Headers:**" in content
    assert "  - `content-security-policy`" in content
    assert "- **Technology Hints:**" in content
    assert "  - `server:test`" in content
    assert "- **Response Headers:**" in content
    assert "  - `Server`: test" in content
    assert "## Endpoint Discovery" in content
    assert "### http://example.com" in content
    assert "`/api` - **Source:** well-known - **Confidence:** medium - **Status:** 200 - **Content-Type:** application/json" in content
    assert "## DNS Analysis" in content
    assert "## TLS Analysis" in content
    assert "TLSv1.3" in content
    assert "## Interesting Signals" in content
    assert "Missing Content-Security-Policy header" in content
    assert "93.184.216.34" in content
    assert "Lookup Error" in content


def test_generate_report_writes_errors(tmp_path):
    output = tmp_path / "report.md"
    results = {
        "Nmap Scan": {"status": {}, "scan_info": {}, "ports": [], "error": "nmap failed"},
        "HTTP Analysis": {"error": "http failed"},
        "DNS Analysis": {"error": "dns failed"},
    }

    generate_report("example.com", results, str(output))

    content = output.read_text(encoding="utf-8")
    assert "nmap failed" in content
    assert "http failed" in content
    assert "dns failed" in content


def test_generate_report_creates_parent_directories(tmp_path):
    output = tmp_path / "reports" / "example_20260617_090807.md"

    generate_report("example.com", {"Nmap Scan": {"status": {}, "scan_info": {}, "ports": []}}, str(output))

    assert output.exists()


def test_generate_report_shows_dns_skip_reason(tmp_path):
    output = tmp_path / "report.md"
    results = {
        "Nmap Scan": {"status": {"state": "up"}, "scan_info": {}, "ports": []},
        "DNS Analysis": {
            "skipped": True,
            "reason": "DNS analysis skipped for IP address target",
            "A": [],
            "MX": [],
            "TXT": [],
        },
    }

    generate_report("127.0.0.1", results, str(output))

    content = output.read_text(encoding="utf-8")
    assert "**Skipped:** DNS analysis skipped for IP address target" in content
    assert "Lookup Error" not in content


def test_generate_report_shows_scan_context_and_filters_http_hsts(tmp_path):
    output = tmp_path / "report.md"
    results = {
        "Nmap Scan": {
            "status": {"state": "up"},
            "scan_info": {},
            "host": "127.0.0.1",
            "ports": [],
        },
        "HTTP Analysis": [{
            "url": "http://127.0.0.1:3000",
            "service": "ppp",
            "status": 200,
            "missing_security_headers": [
                "strict-transport-security",
                "content-security-policy",
            ],
        }],
    }

    generate_report("127.0.0.1", results, str(output))

    content = output.read_text(encoding="utf-8")
    assert "**Scan Context:** Target appears to be local or private." in content
    assert "development, Docker, virtualization, or lab services" in content
    assert "  - `content-security-policy`" in content
    assert "strict-transport-security" not in content
