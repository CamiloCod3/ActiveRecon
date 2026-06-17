import json

from activerecon.targets.target_loader import load_targets


def test_load_targets_from_txt_ignores_comments_and_blanks(tmp_path):
    input_file = tmp_path / "targets.txt"
    input_file.write_text(
        "\n# comment\nexample.com\napi.example.com # inline\n\n",
        encoding="utf-8",
    )

    assert load_targets(input_file) == ["example.com", "api.example.com"]


def test_load_targets_from_json_strings_and_objects(tmp_path):
    input_file = tmp_path / "targets.json"
    input_file.write_text(
        json.dumps([
            "example.com",
            {"url": "https://api.example.com"},
            {"domain": "app.example.com"},
            {"unused": "ignored"},
        ]),
        encoding="utf-8",
    )

    assert load_targets(input_file) == [
        "example.com",
        "https://api.example.com",
        "app.example.com",
    ]


def test_load_targets_from_inventory_like_json(tmp_path):
    input_file = tmp_path / "inventory.json"
    input_file.write_text(
        json.dumps({
            "schema_version": "1.0",
            "targets": [
                {"host": "example.com"},
                {"target": "https://api.example.com"},
            ],
        }),
        encoding="utf-8",
    )

    assert load_targets(input_file) == ["example.com", "https://api.example.com"]


def test_load_targets_from_jsonl(tmp_path):
    input_file = tmp_path / "targets.jsonl"
    input_file.write_text(
        '"example.com"\n{"host": "api.example.com"}\n{"uri": "https://app.example.com"}\n',
        encoding="utf-8",
    )

    assert load_targets(input_file) == [
        "example.com",
        "api.example.com",
        "https://app.example.com",
    ]
