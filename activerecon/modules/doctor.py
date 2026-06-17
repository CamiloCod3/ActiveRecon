import platform
import sys
from pathlib import Path

from .config_loader import get_config_path, load_config
from .nmap_scan import resolve_nmap_executable


MIN_PYTHON = (3, 6)


def _line(status, label, detail):
    return f"{status:<4} {label}: {detail}"


def _check_python():
    version = sys.version_info
    version_text = platform.python_version()
    if version >= MIN_PYTHON:
        return _line("PASS", "Python version", version_text)
    return _line("FAIL", "Python version", f"{version_text} (requires >= 3.6)")


def _check_config():
    try:
        config = load_config()
        return config, _line("PASS", "Config loading", str(get_config_path()))
    except Exception as e:
        return {}, _line("FAIL", "Config loading", str(e))


def _configured_nmap_path(config):
    if not isinstance(config, dict):
        return None
    configured = config.get("nmap_executable") or config.get("nmap_path")
    return str(configured).strip() if configured else None


def _check_nmap(config):
    lines = []
    configured = _configured_nmap_path(config)
    if configured and not Path(configured).is_file():
        lines.append(_line("WARN", "Configured Nmap executable", f"not found: {configured}"))

    nmap_path = resolve_nmap_executable(config)
    if nmap_path:
        lines.extend([
            _line("PASS", "Nmap availability", "found"),
            _line("PASS", "Nmap executable", nmap_path),
        ])
        return lines

    lines.extend([
        _line("FAIL", "Nmap availability", "not found"),
        _line("FAIL", "Nmap executable", "not resolved"),
    ])
    return lines


def _check_reports_dir(reports_dir):
    reports_path = Path(reports_dir)
    probe = reports_path / ".doctor_write_test"
    try:
        reports_path.mkdir(parents=True, exist_ok=True)
        probe.write_text("ok", encoding="utf-8")
        if probe.exists():
            probe.unlink()
        return _line("PASS", "Reports directory writable", str(reports_path))
    except OSError as e:
        return _line("FAIL", "Reports directory writable", f"{reports_path} ({e})")


def run_doctor(reports_dir="reports", output=print):
    config, config_line = _check_config()
    lines = [
        "ActiveRecon doctor",
        _check_python(),
        config_line,
        *_check_nmap(config),
        _check_reports_dir(reports_dir),
    ]

    for line in lines:
        output(line)
