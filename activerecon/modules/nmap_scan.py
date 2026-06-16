import logging
import shlex
import subprocess
import xml.etree.ElementTree as ET


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


def run_nmap_scan(target, scan_command):
    """
    Runs an Nmap scan with XML output and parses the results.
    """
    command = ["nmap"] + shlex.split(scan_command) + ["-oX", "-", target]
    try:
        logging.info(f"Executing Nmap scan: {command}")
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        logging.error("Nmap executable was not found")
        return _base_result(target, "Nmap executable was not found")
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
