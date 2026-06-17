import pytest

from activerecon import cli
from activerecon.models import ReconOptions, ReconResult, TargetSpec


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
