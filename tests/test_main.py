import sys
from datetime import datetime
from pathlib import Path

import activerecon.main as main_module


def test_build_report_path_defaults_to_timestamped_reports_dir():
    report_path = main_module.build_report_path(
        "https://example.com:443/path",
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert report_path == str(Path("reports") / "https_example.com_443_path_20260617_090807.md")


def test_build_report_path_respects_explicit_output():
    assert main_module.build_report_path("example.com", "custom.md") == "custom.md"


def test_main_smoke_with_mocked_modules(monkeypatch, tmp_path):
    output = tmp_path / "report.md"
    captured = {}

    def fake_nmap(target, scan_command):
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

    def fake_dns(target):
        return {"A": ["192.0.2.10"], "MX": [], "TXT": []}

    def fake_report(target, results, output_file):
        captured["results"] = results
        captured["output_file"] = output_file

    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(main_module, "run_nmap_scan", fake_nmap)
    monkeypatch.setattr(main_module, "analyze_http", fake_http)
    monkeypatch.setattr(main_module, "analyze_dns", fake_dns)
    monkeypatch.setattr(main_module, "generate_report", fake_report)
    monkeypatch.setattr(
        sys,
        "argv",
        ["activerecon", "--target", "example.com", "--scan-profile", "fast", "--output", str(output)],
    )

    main_module.main()

    assert captured["http_ports"] == [{"portid": "80", "protocol": "tcp", "state": "open", "service": "http"}]
    assert captured["results"]["Nmap Scan"]["status"]["state"] == "up"
    assert captured["output_file"] == str(output)


def test_main_handles_failed_nmap_without_http(monkeypatch, tmp_path):
    output = tmp_path / "report.md"
    captured = {}

    def fake_http(target, config, http_ports):
        raise AssertionError("HTTP analysis should not run without HTTP ports")

    def fake_report(target, results, output_file):
        captured["results"] = results

    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(
        main_module,
        "run_nmap_scan",
        lambda target, scan_command: {"target": target, "ports": [], "error": "nmap failed"},
    )
    monkeypatch.setattr(main_module, "analyze_http", fake_http)
    monkeypatch.setattr(main_module, "analyze_dns", lambda target: {"A": [], "MX": [], "TXT": []})
    monkeypatch.setattr(main_module, "generate_report", fake_report)
    monkeypatch.setattr(
        sys,
        "argv",
        ["activerecon", "--target", "example.com", "--scan-profile", "fast", "--output", str(output)],
    )

    main_module.main()

    assert captured["results"]["Nmap Scan"]["error"] == "nmap failed"
    assert captured["results"]["HTTP Analysis"] == []


def test_main_uses_timestamped_default_output(monkeypatch):
    captured = {}

    def fake_report(target, results, output_file):
        captured["output_file"] = output_file

    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(
        main_module,
        "run_nmap_scan",
        lambda target, scan_command: {"target": target, "ports": [], "status": {}, "scan_info": {}},
    )
    monkeypatch.setattr(main_module, "analyze_dns", lambda target: {"A": [], "MX": [], "TXT": []})
    monkeypatch.setattr(main_module, "generate_report", fake_report)
    monkeypatch.setattr(
        main_module,
        "datetime",
        type("FixedDatetime", (), {"now": staticmethod(lambda: datetime(2026, 6, 17, 9, 8, 7))}),
    )
    monkeypatch.setattr(sys, "argv", ["activerecon", "--target", "example.com", "--scan-profile", "fast"])

    main_module.main()

    assert captured["output_file"] == str(Path("reports") / "example.com_20260617_090807.md")
