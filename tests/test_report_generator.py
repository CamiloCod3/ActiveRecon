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
            "status": 200,
            "headers": {"Server": "test"},
        }],
        "DNS Analysis": {
            "A": ["192.0.2.10"],
            "MX": [],
            "TXT": [],
            "errors": {"MX": "missing"},
        },
    }

    generate_report("example.com", results, str(output))

    content = output.read_text(encoding="utf-8")
    assert "# Active Recon Report" in content
    assert "## HTTP Analysis" in content
    assert "http://example.com:80" in content
    assert "## DNS Analysis" in content
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
