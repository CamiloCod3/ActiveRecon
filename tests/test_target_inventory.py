from activerecon.policies.scope_policy import ScopePolicy
from activerecon.targets.target_inventory import (
    build_inventory,
    export_scope_file,
    inventory_target_key,
    load_inventory,
    save_inventory,
)
from activerecon.targets.parser import parse_target


def test_build_inventory_normalizes_and_deduplicates_targets():
    inventory = build_inventory(
        [
            "https://API.example.com/",
            "https://api.example.com",
            "http://api.example.com",
            "",
        ],
        generated_at="2026-06-17T18:05:44Z",
    )

    assert inventory["schema_version"] == "1.0"
    assert inventory["generated_at"] == "2026-06-17T18:05:44Z"
    assert inventory["source"] == "manual"
    assert len(inventory["targets"]) == 2
    assert inventory["targets"][0]["host"] == "api.example.com"
    assert inventory["targets"][0]["scheme"] == "https"
    assert inventory["targets"][0]["is_ip"] is False
    assert inventory["targets"][1]["scheme"] == "http"


def test_inventory_target_key_is_stable_for_trailing_slash():
    first = parse_target("https://example.com/")
    second = parse_target("https://example.com")

    assert inventory_target_key(first) == inventory_target_key(second)


def test_save_and_load_inventory(tmp_path):
    output = tmp_path / "inventories" / "latest.json"
    inventory = build_inventory(["example.com"], generated_at="2026-06-17T18:05:44Z")

    save_inventory(inventory, output)

    assert load_inventory(output) == inventory


def test_export_scope_file_works_with_scope_policy(tmp_path):
    scope_file = tmp_path / "scopes" / "latest.txt"
    inventory = build_inventory([
        "https://api.example.com",
        "https://api.example.com/login",
        "192.0.2.10",
    ])

    export_scope_file(inventory, scope_file)

    content = scope_file.read_text(encoding="utf-8").splitlines()
    assert content == ["api.example.com", "192.0.2.10"]

    policy = ScopePolicy.from_file(scope_file)
    assert policy.allows("api.example.com")
    assert policy.allows("192.0.2.10")
    assert not policy.allows("example.net")
