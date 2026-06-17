from activerecon.modules.report_generator import generate_report


def test_generate_report_writes_nested_results(tmp_path):
    output = tmp_path / "report.md"
    results = {
        "Nmap Scan": {
            "status": {"state": "up"},
            "scan_info": {"protocol": "tcp", "numservices": "100"},
            "host": "192.0.2.10",
            "ports": [{
                "portid": "80",
                "protocol": "tcp",
                "state": "open",
                "service": "http",
            }],
        },
        "HTTP Analysis": [{
            "url": "http://example.com:80",
            "final_url": "https://example.com/login",
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
    assert "## HTTP Analysis" in content
    assert "http://example.com:80" in content
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
    assert "## DNS Analysis" in content
    assert "## TLS Analysis" in content
    assert "TLSv1.3" in content
    assert "## Interesting Signals" in content
    assert "Missing Content-Security-Policy header" in content
    assert "192.0.2.10" in content
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
