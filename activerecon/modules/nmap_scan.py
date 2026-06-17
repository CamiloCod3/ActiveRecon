import logging
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


WINDOWS_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]
DEFAULT_NMAP_TIMEOUT = 300


def _base_result(target, error=None):
    result = {
        "target": target,
        "ports": [],
        "status": {"state": "unknown"},
        "scan_info": {},
        "host": "Unknown",
    }
    if error:
        result["error"] = error
    return result


def _node_attrs(node):
    return node.attrib if node is not None else {}


def _configured_nmap_path(config):
    if not isinstance(config, dict):
        return None
    configured = config.get("nmap_executable") or config.get("nmap_path")
    return str(configured).strip() if configured else None


def resolve_nmap_executable(config=None):
    configured = _configured_nmap_path(config)
    if configured and Path(configured).is_file():
        return configured

    path_match = shutil.which("nmap")
    if path_match:
        return path_match

    for candidate in WINDOWS_NMAP_PATHS:
        if Path(candidate).is_file():
            return candidate

    return None


def _nmap_timeout(config):
    if not isinstance(config, dict):
        return DEFAULT_NMAP_TIMEOUT
    configured_timeout = config.get("nmap_timeout", DEFAULT_NMAP_TIMEOUT)
    if configured_timeout in (None, ""):
        return DEFAULT_NMAP_TIMEOUT
    try:
        timeout = float(configured_timeout)
        return int(timeout) if timeout.is_integer() else timeout
    except (TypeError, ValueError):
        logging.warning(f"Invalid nmap_timeout value {configured_timeout!r}; using {DEFAULT_NMAP_TIMEOUT}")
        return DEFAULT_NMAP_TIMEOUT


def run_nmap_scan(target, scan_command, config=None):
    """
    Runs an Nmap scan with XML output and parses the results.
    """
    nmap_executable = resolve_nmap_executable(config)
    if not nmap_executable:
        logging.error("Nmap executable was not found")
        return _base_result(target, "Nmap executable was not found")

    command = [nmap_executable] + shlex.split(scan_command) + ["-oX", "-", target]
    timeout = _nmap_timeout(config)
    try:
        logging.info(f"Executing Nmap scan: {command}")
        logging.debug(f"Using Nmap timeout: {timeout} seconds")
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        error = f"Nmap scan timed out after {timeout} seconds"
        logging.error(error)
        return _base_result(target, error)
    except Exception as e:
        logging.error(f"Failed to execute Nmap scan: {e}")
        return _base_result(target, f"Failed to execute Nmap scan: {e}")

    xml_output = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if not xml_output:
        error = stderr or "Nmap did not return XML output"
        logging.error(error)
        return _base_result(target, error)

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        error = f"Failed to parse Nmap XML output: {e}"
        logging.error(error)
        return _base_result(target, error)

    status_node = root.find(".//status")
    scan_info_node = root.find("scaninfo")
    address_node = root.find("host/address")

    scan_results = _base_result(target)
    scan_results["status"] = _node_attrs(status_node) or {"state": "unknown"}
    scan_results["scan_info"] = _node_attrs(scan_info_node)
    scan_results["host"] = _node_attrs(address_node).get("addr", "Unknown")

    for port in root.findall(".//port"):
        state_node = port.find("state")
        service_node = port.find("service")
        port_data = {
            "portid": port.attrib.get("portid", "Unknown"),
            "protocol": port.attrib.get("protocol", "Unknown"),
            "state": _node_attrs(state_node).get("state", "unknown"),
            "service": _node_attrs(service_node).get("name", "Unknown"),
        }
        scan_results["ports"].append(port_data)

    if result.returncode != 0:
        scan_results["error"] = stderr or f"Nmap exited with status {result.returncode}"

    return scan_results
