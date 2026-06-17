import json
from datetime import datetime
from pathlib import Path


SCHEMA_VERSION = "1.0"


def build_json_payload(target, results, generated_at=None):
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at or datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "target": target,
        "results": results,
    }


def generate_json_report(target, results, output_file, generated_at=None):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(build_json_payload(target, results, generated_at), f, indent=2, sort_keys=True)
        f.write("\n")
