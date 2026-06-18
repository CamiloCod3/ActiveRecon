import json

import pytest

from activerecon import cli
from activerecon.models import ReconOptions, ReconResult, TargetSpec
from activerecon.targets.target_inventory import build_inventory, save_inventory


def _sample_result():
    return ReconResult(
        target="127.0.0.1",
        target_spec=TargetSpec(raw="127.0.0.1", host="127.0.0.1", is_ip=True),
        scan_profile="web",
        markdown_output="reports\\juice-shop_20260617_180544.md",
        json_output="reports\\juice-shop_20260617_180544.json",
        results={
            "Nmap Scan": {
                "status": {"state": "up"},
                "ports": [
                    {"portid": "80", "state": "open"},
                    {"portid": "443", "state": "closed"},
                ],
            },
            "HTTP Analysis": [{"url": "http://127.0.0.1:80", "status": 200}],
            "TLS Analysis": [],
            "DNS Analysis": {
                "skipped": True,
                "reason": "DNS analysis skipped for IP address target",
                "A": [],
                "MX": [],
                "TXT": [],
            },
            "Endpoint Discovery": [{
                "base_url": "http://127.0.0.1",
                "endpoints": [
                    {"path": "/api"},
                    {"path": "/login"},
                    {"path": "/api"},
                ],
            }],
            "Attention": [{"severity": "info", "message": "signal"}],
            "Interesting Signals": [{"severity": "info", "message": "signal"}],
        },
    )


def test_options_from_args_preserves_cli_flags():
    parser = cli.build_parser()
    args = parser.parse_args([
        "--target",
        "example.com",
        "--scan-profile",
        "web",
        "--output",
        "report",
        "--output-format",
        "json",
        "--scope",
        "scope.txt",
        "--dry-run",
        "--verbose",
    ])

    assert cli.options_from_args(args) == ReconOptions(
        target="example.com",
        scan_profile="web",
        output="report",
        output_format="json",
        scope="scope.txt",
        dry_run=True,
        verbose=True,
        quiet=False,
    )


def test_cli_doctor_skips_recon(monkeypatch):
    called = []

    monkeypatch.setattr(cli, "run_doctor", lambda reports_dir: called.append(reports_dir))
    monkeypatch.setattr(cli, "run_recon", lambda options: (_ for _ in ()).throw(AssertionError()))

    assert cli.main(["--doctor"]) == 0
    assert called == [cli.DEFAULT_REPORT_DIR]


def test_cli_requires_target_without_doctor():
    with pytest.raises(SystemExit) as exc:
        cli.main([])

    assert exc.value.code == 2


def test_cli_calls_runner_and_prints_clean_summary(monkeypatch, capsys):
    captured = {}

    def fake_run_recon(options):
        captured["options"] = options
        return _sample_result()

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)

    result = cli.main(["--target", "127.0.0.1", "--scan-profile", "web"])
    captured_output = capsys.readouterr()

    assert result == 0
    assert captured["options"].target == "127.0.0.1"
    assert "ReconResult(" not in captured_output.out
    assert "ActiveRecon scan completed" in captured_output.out
    assert "Target: 127.0.0.1" in captured_output.out
    assert "Profile: web" in captured_output.out
    assert "Nmap: 2 ports listed, 1 open" in captured_output.out
    assert "HTTP: 1 service analyzed" in captured_output.out
    assert "TLS: 0 HTTPS services analyzed" in captured_output.out
    assert "DNS: skipped for IP target" in captured_output.out
    assert "Endpoints: 2 discovered" in captured_output.out
    assert "Interesting Signals: 1" in captured_output.out
    assert "- Markdown: reports\\juice-shop_20260617_180544.md" in captured_output.out
    assert "- JSON: reports\\juice-shop_20260617_180544.json" in captured_output.out


def test_cli_quiet_suppresses_summary_but_keeps_report_paths(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_recon", lambda options: _sample_result())

    result = cli.main(["--target", "127.0.0.1", "--scan-profile", "web", "--quiet"])
    captured_output = capsys.readouterr()

    assert result == 0
    assert "ActiveRecon scan completed" not in captured_output.out
    assert "Nmap:" not in captured_output.out
    assert "Markdown: reports\\juice-shop_20260617_180544.md" in captured_output.out
    assert "JSON: reports\\juice-shop_20260617_180544.json" in captured_output.out


def test_cli_verbose_enables_detailed_logging(monkeypatch):
    captured = {}

    monkeypatch.setattr(cli, "run_recon", lambda options: _sample_result())
    monkeypatch.setattr(
        cli,
        "configure_logging",
        lambda verbose=False, quiet=False: captured.update(verbose=verbose, quiet=quiet),
    )

    assert cli.main(["--target", "127.0.0.1", "--verbose"]) == 0
    assert captured == {"verbose": True, "quiet": False}


def test_cli_dry_run_still_passes_scan_option(monkeypatch):
    captured = {}

    def fake_run_recon(options):
        captured["options"] = options
        result = _sample_result()
        result.dry_run = True
        result.results = {}
        return result

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)

    assert cli.main(["--target", "example.com", "--dry-run"]) == 0
    assert captured["options"].dry_run is True


def test_cli_targets_import_does_not_scan(monkeypatch, tmp_path, capsys):
    input_file = tmp_path / "targets.txt"
    output_file = tmp_path / "inventories" / "latest.json"
    input_file.write_text("example.com\nexample.com\nhttps://api.example.com\n", encoding="utf-8")
    monkeypatch.setattr(cli, "run_recon", lambda options: (_ for _ in ()).throw(AssertionError()))

    result = cli.main([
        "targets",
        "import",
        "--input",
        str(input_file),
        "--output",
        str(output_file),
    ])
    captured_output = capsys.readouterr()

    assert result == 0
    assert output_file.exists()
    assert "ActiveRecon target import completed" in captured_output.out
    assert "Targets loaded: 3" in captured_output.out
    assert "Unique targets: 2" in captured_output.out
    assert "Duplicates removed: 1" in captured_output.out
    assert "Scans run: 0" in captured_output.out

    inventory = json.loads(output_file.read_text(encoding="utf-8"))
    assert [item["host"] for item in inventory["targets"]] == ["example.com", "api.example.com"]


def test_cli_targets_diff_does_not_scan(monkeypatch, tmp_path, capsys):
    previous = tmp_path / "old.json"
    current = tmp_path / "latest.json"
    save_inventory(build_inventory(["example.com", "old.example.com"]), previous)
    save_inventory(build_inventory(["example.com", "new.example.com"]), current)
    monkeypatch.setattr(cli, "run_recon", lambda options: (_ for _ in ()).throw(AssertionError()))

    result = cli.main([
        "targets",
        "diff",
        "--previous",
        str(previous),
        "--current",
        str(current),
    ])
    captured_output = capsys.readouterr()

    assert result == 0
    assert "ActiveRecon target diff completed" in captured_output.out
    assert "Added: 1" in captured_output.out
    assert "Removed: 1" in captured_output.out
    assert "Unchanged: 1" in captured_output.out
    assert "Scans run: 0" in captured_output.out


def test_cli_targets_export_scope_does_not_scan(monkeypatch, tmp_path, capsys):
    inventory_file = tmp_path / "latest.json"
    scope_file = tmp_path / "scopes" / "latest.txt"
    save_inventory(build_inventory(["https://api.example.com", "https://api.example.com/login"]), inventory_file)
    monkeypatch.setattr(cli, "run_recon", lambda options: (_ for _ in ()).throw(AssertionError()))

    result = cli.main([
        "targets",
        "export-scope",
        "--inventory",
        str(inventory_file),
        "--output",
        str(scope_file),
    ])
    captured_output = capsys.readouterr()

    assert result == 0
    assert scope_file.read_text(encoding="utf-8").splitlines() == ["api.example.com"]
    assert "ActiveRecon scope export completed" in captured_output.out
    assert "Targets exported: 1" in captured_output.out
    assert "Scans run: 0" in captured_output.out


def test_cli_scope_check_allowed_and_runs_zero_scans(monkeypatch, tmp_path, capsys):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({
            "schema_version": "1.0",
            "program": "Example Program",
            "allowed": {"wildcards": ["*.example.com"]},
            "denied": {},
            "rules": {"notes": "test"},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "run_recon", lambda options: (_ for _ in ()).throw(AssertionError()))

    result = cli.main([
        "scope",
        "check",
        "--target",
        "api.example.com",
        "--scope",
        str(scope_file),
    ])
    captured_output = capsys.readouterr()

    assert result == 0
    assert "ActiveRecon scope check completed" in captured_output.out
    assert "Target: api.example.com" in captured_output.out
    assert f"Scope: {scope_file}" in captured_output.out
    assert "Allowed: yes" in captured_output.out
    assert "Program: Example Program" in captured_output.out
    assert "Scans run: 0" in captured_output.out


def test_cli_scope_check_url_allow_still_runs_zero_scans(monkeypatch, tmp_path, capsys):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({
            "schema_version": "2.0",
            "program": "Example Program",
            "allowed": {"urls": ["https://api.example.com/login"]},
            "denied": {},
            "rules": {},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "run_recon", lambda options: (_ for _ in ()).throw(AssertionError()))

    result = cli.main([
        "scope",
        "check",
        "--target",
        "https://api.example.com/login",
        "--scope",
        str(scope_file),
    ])
    captured_output = capsys.readouterr()

    assert result == 0
    assert "Allowed: yes" in captured_output.out
    assert "allowed.urls" in captured_output.out
    assert "Scans run: 0" in captured_output.out


def test_cli_scope_check_denied_and_runs_zero_scans(monkeypatch, tmp_path, capsys):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({
            "schema_version": "1.0",
            "program": "Example Program",
            "allowed": {"wildcards": ["*.example.com"]},
            "denied": {"domains": ["admin.example.com"]},
            "rules": {},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "run_recon", lambda options: (_ for _ in ()).throw(AssertionError()))

    result = cli.main([
        "scope",
        "check",
        "--target",
        "admin.example.com",
        "--scope",
        str(scope_file),
    ])
    captured_output = capsys.readouterr()

    assert result == 0
    assert "Allowed: no" in captured_output.out
    assert "denied.domains" in captured_output.out
    assert "Scans run: 0" in captured_output.out
