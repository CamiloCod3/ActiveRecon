import re
from datetime import datetime
from pathlib import Path


DEFAULT_REPORT_DIR = "reports"


def _safe_report_name(target):
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(target)).strip("._-")
    return safe_name or "target"


def build_report_path(target, output=None, now=None, suffix=".md"):
    timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")

    if output:
        output_path = Path(output)
        output_dir = output_path.parent if output_path.parent != Path(".") else Path(DEFAULT_REPORT_DIR)
        stem = _safe_report_name(output_path.stem)
    else:
        output_dir = Path(DEFAULT_REPORT_DIR)
        stem = _safe_report_name(target)

    filename = f"{stem}_{timestamp}{suffix}"
    return str(output_dir / filename)


def build_output_paths(target, output=None, output_format="both", now=None):
    now = now or datetime.now()
    markdown_path = build_report_path(target, output, now, ".md")
    markdown = markdown_path if output_format in {"md", "both"} else None

    json_path = build_report_path(target, output, now, ".json")
    json_output = json_path if output_format in {"json", "both"} else None
    return markdown, json_output
