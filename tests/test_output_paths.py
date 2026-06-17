from datetime import datetime
from pathlib import Path

from activerecon.output_paths import build_output_paths, build_report_path


def test_build_report_path_defaults_to_timestamped_reports_dir():
    report_path = build_report_path(
        "https://example.com:443/path",
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert report_path == str(Path("reports") / "https_example.com_443_path_20260617_090807.md")


def test_build_report_path_respects_explicit_output():
    report_path = build_report_path(
        "example.com",
        "custom.md",
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert report_path == str(Path("reports") / "custom_20260617_090807.md")


def test_build_report_path_respects_explicit_output_directory(tmp_path):
    report_path = build_report_path(
        "example.com",
        str(tmp_path / "custom.md"),
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert report_path == str(tmp_path / "custom_20260617_090807.md")


def test_build_output_paths_defaults_to_markdown_and_json():
    markdown, json_output = build_output_paths(
        "example.com",
        output_format="both",
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert markdown == str(Path("reports") / "example.com_20260617_090807.md")
    assert json_output == str(Path("reports") / "example.com_20260617_090807.json")


def test_build_output_paths_json_only_uses_explicit_output():
    markdown, json_output = build_output_paths(
        "example.com",
        "custom.json",
        "json",
        now=datetime(2026, 6, 17, 9, 8, 7),
    )

    assert markdown is None
    assert json_output == str(Path("reports") / "custom_20260617_090807.json")


def test_build_output_paths_bare_output_stays_in_reports_with_timestamp():
    markdown, json_output = build_output_paths(
        "scanme.nmap.org",
        "report.md",
        "both",
        now=datetime(2026, 6, 17, 10, 28, 5),
    )

    assert markdown == str(Path("reports") / "report_20260617_102805.md")
    assert json_output == str(Path("reports") / "report_20260617_102805.json")
