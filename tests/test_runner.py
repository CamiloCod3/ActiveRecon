from activerecon import runner
from activerecon.models import ReconOptions


def _fixed_output_paths(target, output, output_format):
    markdown = "reports/report.md" if output_format in {"md", "both"} else None
    json_output = "reports/report.json" if output_format in {"json", "both"} else None
    return markdown, json_output


def test_runner_smoke_with_mocked_modules(monkeypatch):
    captured = {}

    def fake_nmap(target, scan_command, config):
        assert target == "example.com"
        assert scan_command == "-Pn"
        return {
            "target": target,
            "ports": [{"portid": "80", "protocol": "tcp", "state": "open", "service": "http"}],
            "status": {"state": "up"},
            "scan_info": {},
            "host": "example.com",
        }

    def fake_http(target, config, http_ports):
        captured["http_ports"] = http_ports
        return [{"url": "http://example.com:80", "status": 200, "headers": {}}]

    def fake_report(target, results, output_file):
        captured["results"] = results
        captured["markdown_output"] = output_file

    def fake_json_report(target, results, output_file, **kwargs):
        captured["json_output"] = output_file
        captured["json_kwargs"] = kwargs

    monkeypatch.setattr(runner, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(runner, "build_output_paths", _fixed_output_paths)
    monkeypatch.setattr(runner, "run_nmap_scan", fake_nmap)
    monkeypatch.setattr(runner, "analyze_http", fake_http)
    monkeypatch.setattr(runner, "analyze_tls", lambda http_results, timeout: [])
    monkeypatch.setattr(runner, "analyze_dns", lambda target: {"A": ["192.0.2.10"], "MX": [], "TXT": []})
    monkeypatch.setattr(runner, "generate_attention_findings", lambda results: [])
    monkeypatch.setattr(runner, "generate_report", fake_report)
    monkeypatch.setattr(runner, "generate_json_report", fake_json_report)

    result = runner.run_recon(ReconOptions(target="example.com", scan_profile="fast"))

    assert captured["http_ports"] == [{"portid": "80", "protocol": "tcp", "state": "open", "service": "http"}]
    assert result.results["Nmap Scan"]["status"]["state"] == "up"
    assert result.results["Interesting Signals"] == result.results["Attention"]
    assert captured["markdown_output"] == "reports/report.md"
    assert captured["json_output"] == "reports/report.json"
    assert captured["json_kwargs"]["scan_profile"] == "fast"


def test_runner_handles_failed_nmap_without_http(monkeypatch):
    captured = {}

    monkeypatch.setattr(runner, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(runner, "build_output_paths", _fixed_output_paths)
    monkeypatch.setattr(
        runner,
        "run_nmap_scan",
        lambda target, scan_command, config: {"target": target, "ports": [], "error": "nmap failed"},
    )
    monkeypatch.setattr(
        runner,
        "analyze_http",
        lambda target, config, http_ports: (_ for _ in ()).throw(AssertionError()),
    )
    monkeypatch.setattr(runner, "analyze_tls", lambda http_results, timeout: [])
    monkeypatch.setattr(runner, "analyze_dns", lambda target: {"A": [], "MX": [], "TXT": []})
    monkeypatch.setattr(runner, "generate_attention_findings", lambda results: [])
    monkeypatch.setattr(
        runner,
        "generate_report",
        lambda target, results, output_file: captured.update(results=results),
    )
    monkeypatch.setattr(runner, "generate_json_report", lambda target, results, output_file, **kwargs: None)

    result = runner.run_recon(ReconOptions(target="example.com", scan_profile="fast"))

    assert result.results["Nmap Scan"]["error"] == "nmap failed"
    assert captured["results"]["HTTP Analysis"] == []
    assert captured["results"]["TLS Analysis"] == []


def test_runner_dry_run_skips_scanning(monkeypatch):
    monkeypatch.setattr(runner, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(runner, "build_output_paths", _fixed_output_paths)
    monkeypatch.setattr(
        runner,
        "run_nmap_scan",
        lambda target, scan_command, config: (_ for _ in ()).throw(AssertionError()),
    )

    result = runner.run_recon(ReconOptions(target="example.com", scan_profile="fast", dry_run=True))

    assert result.dry_run
    assert result.results == {}


def test_runner_skips_dns_for_ip_target(monkeypatch):
    captured = {}

    monkeypatch.setattr(runner, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(runner, "build_output_paths", _fixed_output_paths)
    monkeypatch.setattr(
        runner,
        "run_nmap_scan",
        lambda target, scan_command, config: {
            "target": target,
            "ports": [{"portid": "3000", "protocol": "tcp", "state": "open", "service": "ppp"}],
            "status": {"state": "up"},
            "scan_info": {},
            "host": target,
        },
    )
    monkeypatch.setattr(
        runner,
        "analyze_dns",
        lambda target: (_ for _ in ()).throw(AssertionError("DNS should be skipped for IP targets")),
    )
    monkeypatch.setattr(
        runner,
        "analyze_http",
        lambda target, config, http_ports: captured.setdefault("http_ports", http_ports) or [],
    )
    monkeypatch.setattr(runner, "analyze_tls", lambda http_results, timeout: [])
    monkeypatch.setattr(runner, "generate_attention_findings", lambda results: [])
    monkeypatch.setattr(runner, "generate_report", lambda target, results, output_file: None)
    monkeypatch.setattr(runner, "generate_json_report", lambda target, results, output_file, **kwargs: None)

    result = runner.run_recon(ReconOptions(target="127.0.0.1", scan_profile="fast"))

    assert captured["http_ports"] == [{"portid": "3000", "protocol": "tcp", "state": "open", "service": "ppp"}]
    assert result.results["DNS Analysis"] == {
        "skipped": True,
        "reason": "DNS analysis skipped for IP address target",
        "A": [],
        "MX": [],
        "TXT": [],
    }


def test_runner_web_profile_runs_endpoint_discovery(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        runner,
        "CONFIG",
        {
            "scan_profiles": {"web": "-web"},
            "http_timeout": 5,
            "web_recon": {"enabled_profiles": ["web"]},
        },
    )
    monkeypatch.setattr(runner, "build_output_paths", _fixed_output_paths)
    monkeypatch.setattr(
        runner,
        "run_nmap_scan",
        lambda target, scan_command, config: {
            "target": target,
            "ports": [{"portid": "3000", "protocol": "tcp", "state": "open", "service": "ppp"}],
            "status": {"state": "up"},
            "scan_info": {},
            "host": target,
        },
    )
    monkeypatch.setattr(
        runner,
        "analyze_http",
        lambda target, config, http_ports: [{"url": "http://example.com:3000", "status": 200, "headers": {}}],
    )
    monkeypatch.setattr(runner, "analyze_tls", lambda http_results, timeout: [])
    def fake_endpoints(http_results, config):
        captured["endpoint_http_results"] = http_results
        return [{"base_url": "http://example.com:3000", "endpoints": [{"path": "/api"}]}]

    monkeypatch.setattr(runner, "discover_endpoints", fake_endpoints)
    monkeypatch.setattr(runner, "analyze_dns", lambda target: {"A": [], "MX": [], "TXT": []})
    monkeypatch.setattr(runner, "generate_attention_findings", lambda results: [])
    monkeypatch.setattr(runner, "generate_report", lambda target, results, output_file: None)
    monkeypatch.setattr(runner, "generate_json_report", lambda target, results, output_file, **kwargs: None)

    result = runner.run_recon(ReconOptions(target="example.com", scan_profile="web"))

    assert captured["endpoint_http_results"] == [{"url": "http://example.com:3000", "status": 200, "headers": {}}]
    assert result.results["Endpoint Discovery"][0]["endpoints"][0]["path"] == "/api"
