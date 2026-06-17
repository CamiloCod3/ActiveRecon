import json

from activerecon.modules.json_report import build_json_payload, generate_json_report


def test_build_json_payload_wraps_results_with_schema():
    payload = build_json_payload("example.com", {"Nmap Scan": {"ports": []}}, "2026-06-17T09:08:07Z")

    assert payload["schema_version"] == "1.0"
    assert payload["generated_at"] == "2026-06-17T09:08:07Z"
    assert payload["target"] == "example.com"
    assert payload["results"]["Nmap Scan"]["ports"] == []


def test_generate_json_report_writes_file(tmp_path):
    output = tmp_path / "reports" / "example.json"

    generate_json_report("example.com", {"Attention": []}, str(output), "2026-06-17T09:08:07Z")

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["target"] == "example.com"
    assert data["results"]["Attention"] == []
