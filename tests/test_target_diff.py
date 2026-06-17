from activerecon.targets.target_diff import diff_inventories
from activerecon.targets.target_inventory import build_inventory


def test_diff_inventories_reports_added_removed_and_unchanged():
    previous = build_inventory(
        ["example.com", "old.example.com", "https://api.example.com"],
        generated_at="2026-06-17T18:00:00Z",
    )
    current = build_inventory(
        ["example.com", "new.example.com", "https://api.example.com"],
        generated_at="2026-06-17T18:05:00Z",
    )

    diff = diff_inventories(previous, current)

    assert [item["host"] for item in diff["added"]] == ["new.example.com"]
    assert [item["host"] for item in diff["removed"]] == ["old.example.com"]
    assert [item["host"] for item in diff["unchanged"]] == ["api.example.com", "example.com"]
