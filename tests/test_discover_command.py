import json
from types import SimpleNamespace

from activerecon.commands import discover_command


def _args(tmp_path, scope=None):
    return SimpleNamespace(
        discover_action="subdomains",
        domain="example.com",
        scope=str(scope) if scope else None,
        output=str(tmp_path / "inventories" / "discovered.json"),
    )


def test_discover_command_writes_inventory_with_scope_counts(monkeypatch, tmp_path):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({
            "schema_version": "2.0",
            "program": "Example Program",
            "allowed": {"wildcards": ["*.example.com"]},
            "denied": {"domains": ["admin.example.com"]},
            "rules": {},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(discover_command, "load_config", lambda: {})
    monkeypatch.setattr(
        discover_command,
        "run_subfinder",
        lambda domain, config: [
            "api.example.com",
            "admin.example.com",
            "outside.test",
            "api.example.com",
        ],
    )
    output = []

    result = discover_command.run_discover_command(_args(tmp_path, scope_file), output.append)

    assert result == 0
    assert "ActiveRecon passive subdomain discovery completed" in output
    assert "Domain: example.com" in output
    assert "Provider: subfinder" in output
    assert "Discovered: 3" in output
    assert "In scope: 1" in output
    assert "Out of scope: 2" in output
    assert "Scans run: 0" in output

    inventory = json.loads((tmp_path / "inventories" / "discovered.json").read_text(encoding="utf-8"))
    assert inventory["schema_version"] == "1.0"
    assert inventory["source"] == "subfinder"
    assert inventory["provider"] == "subfinder"
    assert inventory["domain"] == "example.com"
    assert inventory["metadata"]["scans_run"] == 0
    assert [item["host"] for item in inventory["targets"]] == [
        "api.example.com",
        "admin.example.com",
        "outside.test",
    ]
    assert inventory["targets"][0]["in_scope"] is True
    assert inventory["targets"][0]["matched_section"] == "allowed.wildcards"
    assert inventory["targets"][1]["in_scope"] is False
    assert inventory["targets"][1]["matched_section"] == "denied.domains"
    assert inventory["targets"][2]["in_scope"] is False


def test_discover_command_reports_missing_subfinder_without_scans(monkeypatch, tmp_path):
    monkeypatch.setattr(discover_command, "load_config", lambda: {})

    def missing_subfinder(domain, config):
        raise FileNotFoundError("subfinder executable was not found")

    monkeypatch.setattr(discover_command, "run_subfinder", missing_subfinder)
    output = []

    result = discover_command.run_discover_command(_args(tmp_path), output.append)

    assert result == 2
    assert "ActiveRecon passive subdomain discovery failed" in output
    assert "Error: subfinder executable was not found" in output
    assert "Scans run: 0" in output
    assert not (tmp_path / "inventories" / "discovered.json").exists()
