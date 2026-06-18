import logging
import shutil
import subprocess
from pathlib import Path


DEFAULT_SUBFINDER_TIMEOUT = 120
SUBFINDER_CONFIG_KEYS = ("subfinder_executable", "subfinder_path")


def _configured_subfinder_path(config):
    if not isinstance(config, dict):
        return None
    for key in SUBFINDER_CONFIG_KEYS:
        configured = config.get(key)
        if configured:
            return str(configured).strip()
    return None


def resolve_subfinder_executable(config=None):
    configured = _configured_subfinder_path(config)
    if configured:
        configured_path = Path(configured).expanduser()
        if configured_path.is_file():
            return str(configured_path)
        configured_match = shutil.which(configured)
        if configured_match:
            return configured_match

    for name in ("subfinder", "subfinder.exe"):
        path_match = shutil.which(name)
        if path_match:
            return path_match

    go_bin = Path.home() / "go" / "bin"
    for name in ("subfinder", "subfinder.exe"):
        candidate = go_bin / name
        if candidate.is_file():
            return str(candidate)

    return None


def _subfinder_timeout(config, timeout):
    if timeout not in (None, ""):
        return timeout
    if not isinstance(config, dict):
        return DEFAULT_SUBFINDER_TIMEOUT
    configured_timeout = config.get("subfinder_timeout", DEFAULT_SUBFINDER_TIMEOUT)
    if configured_timeout in (None, ""):
        return DEFAULT_SUBFINDER_TIMEOUT
    try:
        value = float(configured_timeout)
        return int(value) if value.is_integer() else value
    except (TypeError, ValueError):
        logging.warning(
            f"Invalid subfinder_timeout value {configured_timeout!r}; "
            f"using {DEFAULT_SUBFINDER_TIMEOUT}"
        )
        return DEFAULT_SUBFINDER_TIMEOUT


def _parse_subfinder_stdout(stdout):
    return [line.strip() for line in str(stdout or "").splitlines() if line.strip()]


def run_subfinder(domain, config=None, timeout=None):
    executable = resolve_subfinder_executable(config)
    if not executable:
        raise FileNotFoundError(
            "subfinder executable was not found. Install subfinder, add it to PATH, "
            "or set subfinder_executable/subfinder_path in config."
        )

    effective_timeout = _subfinder_timeout(config, timeout)
    command = [executable, "-d", domain, "-silent"]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=effective_timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"subfinder timed out after {effective_timeout} seconds") from e

    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        raise RuntimeError(stderr or f"subfinder exited with status {result.returncode}")

    return _parse_subfinder_stdout(result.stdout)
