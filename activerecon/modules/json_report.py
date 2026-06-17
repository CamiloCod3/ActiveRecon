import copy
import ipaddress
import json
from datetime import datetime
from pathlib import Path

from .endpoint_categories import (
    categorize_endpoints,
    endpoint_category_summary,
    unique_endpoint_paths,
)


SCHEMA_VERSION = "1.1"
TOOL_NAME = "ActiveRecon"
AUTHORIZED_USE_NOTICE = True
HSTS_HEADER = "strict-transport-security"
SCAN_CONTEXT_NOTE = (
    "Target appears to be local or private. Results may include local system, "
    "development, Docker, virtualization, or lab services."
)
def _as_list(value):
    return value if isinstance(value, list) else []


def _nmap_results(results):
    return results.get("Nmap Scan", results) if isinstance(results, dict) else {}


def _is_https_http_item(item):
    url = str(item.get("final_url") or item.get("url") or "").lower()
    return url.startswith("https://")


def _filter_http_security_headers(results):
    http_results = results.get("HTTP Analysis", [])
    if not isinstance(http_results, list):
        return

    for item in http_results:
        if not isinstance(item, dict) or _is_https_http_item(item):
            continue
        missing_headers = item.get("missing_security_headers", [])
        if isinstance(missing_headers, list):
            item["missing_security_headers"] = [
                header
                for header in missing_headers
                if str(header).lower() != HSTS_HEADER
            ]


def _dns_record_count(results):
    dns_results = results.get("DNS Analysis", {})
    if not isinstance(dns_results, dict):
        return 0
    return sum(
        len(records)
        for record_type, records in dns_results.items()
        if record_type != "errors" and isinstance(records, list)
    )


def _endpoint_groups(results):
    endpoint_results = results.get("Endpoint Discovery", [])
    return endpoint_results if isinstance(endpoint_results, list) else []


def _endpoint_count(results):
    paths = set()
    for group in _endpoint_groups(results):
        if isinstance(group, dict):
            paths.update(unique_endpoint_paths(_as_list(group.get("endpoints", []))))
    return len(paths)


def build_json_summary(results):
    nmap_results = _nmap_results(results)
    ports = _as_list(nmap_results.get("ports", []))
    http_results = _as_list(results.get("HTTP Analysis", []))
    tls_results = _as_list(results.get("TLS Analysis", []))
    signals = _as_list(results.get("Attention", results.get("Interesting Signals", [])))

    return {
        "host_status": nmap_results.get("status", {}).get("state", "Unknown"),
        "total_ports_listed": len(ports),
        "open_ports": len([
            port
            for port in ports
            if isinstance(port, dict) and port.get("state") == "open"
        ]),
        "http_services": len(http_results),
        "tls_results": len(tls_results),
        "dns_records": _dns_record_count(results),
        "interesting_signals": len(signals),
        "endpoint_count": _endpoint_count(results),
    }


def _looks_local_or_private(value):
    text = str(value or "").strip()
    if text.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(text)
        return address.is_loopback or address.is_private
    except ValueError:
        return False


def _scan_context(target, results):
    nmap_results = _nmap_results(results)
    if _looks_local_or_private(target) or _looks_local_or_private(nmap_results.get("host")):
        return SCAN_CONTEXT_NOTE
    return None


def build_json_metadata(target, results, scan_profile=None, scan_context=None):
    metadata = {
        "tool": TOOL_NAME,
        "authorized_use_notice": AUTHORIZED_USE_NOTICE,
    }
    if scan_profile:
        metadata["scan_profile"] = scan_profile

    context = scan_context or _scan_context(target, results)
    if context:
        metadata["scan_context"] = context
    return metadata


def _enrich_endpoint_discovery(results):
    for group in _endpoint_groups(results):
        if not isinstance(group, dict):
            continue
        endpoints = _as_list(group.get("endpoints", []))
        categories = categorize_endpoints(endpoints)
        group["summary"] = endpoint_category_summary(endpoints, categories)
        group["categories"] = categories


def normalize_results_for_json(results):
    normalized = copy.deepcopy(results if isinstance(results, dict) else {})
    signals = normalized.get("Attention", normalized.get("Interesting Signals", []))
    if not isinstance(signals, list):
        signals = []
    normalized["Attention"] = signals
    normalized["Interesting Signals"] = signals
    _filter_http_security_headers(normalized)
    _enrich_endpoint_discovery(normalized)
    return normalized


def build_json_payload(target, results, generated_at=None, scan_profile=None, scan_context=None):
    normalized_results = normalize_results_for_json(results)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at or datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "target": target,
        "metadata": build_json_metadata(target, normalized_results, scan_profile, scan_context),
        "summary": build_json_summary(normalized_results),
        "results": normalized_results,
    }


def generate_json_report(target, results, output_file, generated_at=None, scan_profile=None, scan_context=None):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(
            build_json_payload(target, results, generated_at, scan_profile, scan_context),
            f,
            indent=2,
            sort_keys=True,
        )
        f.write("\n")
