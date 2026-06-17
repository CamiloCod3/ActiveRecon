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
    report_path = main_module.build_report_path(
        "example.com",
        "custom.md",
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert report_path == str(Path("reports") / "custom_20260617_090807.md")


def test_build_report_path_respects_explicit_output_directory(tmp_path):
    report_path = main_module.build_report_path(
        "example.com",
        str(tmp_path / "custom.md"),
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert report_path == str(tmp_path / "custom_20260617_090807.md")


def test_main_smoke_with_mocked_modules(monkeypatch, tmp_path):
    output = tmp_path / "report.md"
    captured = {}

    def fake_nmap(target, scan_command, config):
        assert target == "example.com"
        assert scan_command == "-Pn"
        assert config["http_timeout"] == 5
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

    def fake_json_report(target, results, output_file):
        captured["json_output_file"] = output_file

    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(main_module, "run_nmap_scan", fake_nmap)
    monkeypatch.setattr(main_module, "analyze_http", fake_http)
    monkeypatch.setattr(main_module, "analyze_tls", lambda http_results, timeout: [])
    monkeypatch.setattr(main_module, "analyze_dns", fake_dns)
    monkeypatch.setattr(main_module, "generate_attention_findings", lambda results: [])
    monkeypatch.setattr(main_module, "generate_report", fake_report)
    monkeypatch.setattr(main_module, "generate_json_report", fake_json_report)
    monkeypatch.setattr(
        main_module,
        "datetime",
        type("FixedDatetime", (), {"now": staticmethod(lambda: datetime(2026, 6, 17, 9, 8, 7))}),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["activerecon", "--target", "example.com", "--scan-profile", "fast", "--output", str(output)],
    )

    main_module.main()

    assert captured["http_ports"] == [{"portid": "80", "protocol": "tcp", "state": "open", "service": "http"}]
    assert captured["results"]["Nmap Scan"]["status"]["state"] == "up"
    assert captured["output_file"] == str(tmp_path / "report_20260617_090807.md")
    assert captured["json_output_file"] == str(tmp_path / "report_20260617_090807.json")


def test_main_handles_failed_nmap_without_http(monkeypatch, tmp_path):
    output = tmp_path / "report.md"
    captured = {}

    def fake_http(target, config, http_ports):
        raise AssertionError("HTTP analysis should not run without HTTP ports")

    def fake_report(target, results, output_file):
        captured["results"] = results

    def fake_json_report(target, results, output_file):
        captured["json_output_file"] = output_file

    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(
        main_module,
        "run_nmap_scan",
        lambda target, scan_command, config: {"target": target, "ports": [], "error": "nmap failed"},
    )
    monkeypatch.setattr(main_module, "analyze_http", fake_http)
    monkeypatch.setattr(main_module, "analyze_tls", lambda http_results, timeout: [])
    monkeypatch.setattr(main_module, "analyze_dns", lambda target: {"A": [], "MX": [], "TXT": []})
    monkeypatch.setattr(main_module, "generate_attention_findings", lambda results: [])
    monkeypatch.setattr(main_module, "generate_report", fake_report)
    monkeypatch.setattr(main_module, "generate_json_report", fake_json_report)
    monkeypatch.setattr(
        main_module,
        "datetime",
        type("FixedDatetime", (), {"now": staticmethod(lambda: datetime(2026, 6, 17, 9, 8, 7))}),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["activerecon", "--target", "example.com", "--scan-profile", "fast", "--output", str(output)],
    )

    main_module.main()

    assert captured["results"]["Nmap Scan"]["error"] == "nmap failed"
    assert captured["results"]["HTTP Analysis"] == []
    assert captured["results"]["TLS Analysis"] == []


def test_build_output_paths_defaults_to_markdown_and_json():
    markdown, json_output = main_module.build_output_paths(
        "example.com",
        output_format="both",
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert markdown == str(Path("reports") / "example.com_20260617_090807.md")
    assert json_output == str(Path("reports") / "example.com_20260617_090807.json")


def test_build_output_paths_json_only_uses_explicit_output():
    markdown, json_output = main_module.build_output_paths(
        "example.com",
        "custom.json",
        "json",
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert markdown is None
    assert json_output == str(Path("reports") / "custom_20260617_090807.json")


def test_build_output_paths_bare_output_stays_in_reports_with_timestamp():
    markdown, json_output = main_module.build_output_paths(
        "scanme.nmap.org",
        "report.md",
        "both",
        now=datetime(2026, 6, 17, 10, 28, 5),
    )

    assert markdown == str(Path("reports") / "report_20260617_102805.md")
    assert json_output == str(Path("reports") / "report_20260617_102805.json")


def test_main_uses_timestamped_default_output(monkeypatch):
    captured = {}

    def fake_report(target, results, output_file):
        captured["output_file"] = output_file

    def fake_json_report(target, results, output_file):
        captured["json_output_file"] = output_file

    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(
        main_module,
        "run_nmap_scan",
        lambda target, scan_command, config: {"target": target, "ports": [], "status": {}, "scan_info": {}},
    )
    monkeypatch.setattr(main_module, "analyze_tls", lambda http_results, timeout: [])
    monkeypatch.setattr(main_module, "analyze_dns", lambda target: {"A": [], "MX": [], "TXT": []})
    monkeypatch.setattr(main_module, "generate_attention_findings", lambda results: [])
    monkeypatch.setattr(main_module, "generate_report", fake_report)
    monkeypatch.setattr(main_module, "generate_json_report", fake_json_report)
    monkeypatch.setattr(
        main_module,
        "datetime",
        type("FixedDatetime", (), {"now": staticmethod(lambda: datetime(2026, 6, 17, 9, 8, 7))}),
    )
    monkeypatch.setattr(sys, "argv", ["activerecon", "--target", "example.com", "--scan-profile", "fast"])

    main_module.main()

    assert captured["output_file"] == str(Path("reports") / "example.com_20260617_090807.md")
    assert captured["json_output_file"] == str(Path("reports") / "example.com_20260617_090807.json")


def test_main_dry_run_skips_scanning(monkeypatch):
    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(
        main_module,
        "run_nmap_scan",
        lambda target, scan_command, config: (_ for _ in ()).throw(AssertionError()),
    )
    monkeypatch.setattr(sys, "argv", ["activerecon", "--target", "example.com", "--dry-run"])

    main_module.main()


def test_main_doctor_skips_scanning(monkeypatch):
    called = []

    monkeypatch.setattr(main_module, "run_doctor", lambda reports_dir: called.append(reports_dir))
    monkeypatch.setattr(
        main_module,
        "run_nmap_scan",
        lambda target, scan_command, config: (_ for _ in ()).throw(AssertionError()),
    )
    monkeypatch.setattr(sys, "argv", ["activerecon", "--doctor"])

    main_module.main()

    assert called == [main_module.DEFAULT_REPORT_DIR]


def test_main_rejects_target_outside_scope(monkeypatch, tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("allowed.example.com\n", encoding="utf-8")

    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(
        sys,
        "argv",
        ["activerecon", "--target", "example.com", "--scope", str(scope), "--dry-run"],
    )

    try:
        main_module.main()
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("Expected scope validation to reject target")


def test_main_rejects_missing_scope_file(monkeypatch, tmp_path):
    missing_scope = tmp_path / "missing.txt"

    monkeypatch.setattr(main_module, "CONFIG", {"scan_profiles": {"fast": "-Pn"}, "http_timeout": 5})
    monkeypatch.setattr(
        sys,
        "argv",
        ["activerecon", "--target", "example.com", "--scope", str(missing_scope), "--dry-run"],
    )

    try:
        main_module.main()
    except SystemExit as e:
        assert e.code == 2
    else:
        raise AssertionError("Expected missing scope file to reject target")
