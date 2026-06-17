import pytest

from activerecon import cli
from activerecon.models import ReconOptions, ReconResult, TargetSpec


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

    assert cli.main(["--doctor"]) is None
    assert called == [cli.DEFAULT_REPORT_DIR]


def test_cli_requires_target_without_doctor():
    with pytest.raises(SystemExit) as exc:
        cli.main([])

    assert exc.value.code == 2


def test_cli_calls_runner(monkeypatch):
    captured = {}

    def fake_run_recon(options):
        captured["options"] = options
        return ReconResult(
            target=options.target,
            target_spec=TargetSpec(raw=options.target, host=options.target),
            scan_profile=options.scan_profile,
        )

    monkeypatch.setattr(cli, "run_recon", fake_run_recon)

    result = cli.main(["--target", "example.com", "--scan-profile", "fast", "--quiet"])

    assert result.target == "example.com"
    assert captured["options"].quiet is True
