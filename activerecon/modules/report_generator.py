import ipaddress
import logging
from pathlib import PurePosixPath
from pathlib import Path


def _format_error(error):
    return f"\n**Error:** {error}\n" if error else ""


def _as_list(value):
    return value if isinstance(value, list) else []


def _looks_local_or_private(value):
    text = str(value or "").strip()
    if text.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(text)
        return address.is_loopback or address.is_private
    except ValueError:
        return False


def _scan_context_note(target, nmap_results):
    if _looks_local_or_private(target) or _looks_local_or_private(nmap_results.get("host")):
        return (
            "Target appears to be local or private. Results may include local system, "
            "development, Docker, virtualization, or lab services."
        )
    return None


def _is_https_http_item(item):
    url = str(item.get("final_url") or item.get("url") or "").lower()
    return url.startswith("https://")


def _visible_missing_security_headers(item):
    headers = item.get("missing_security_headers", [])
    if not isinstance(headers, list):
        return []
    if _is_https_http_item(item):
        return headers
    return [header for header in headers if header != "strict-transport-security"]


def _write_markdown_list(f, label, values):
    if not values:
        return
    f.write(f"- **{label}:**\n")
    for value in values:
        f.write(f"  - `{value}`\n")


def _write_http_result(f, item):
    f.write(f"- **Nmap Service:** {item.get('service', 'Unknown')}\n")
    f.write("- **Detected HTTP:** yes\n")
    f.write(f"- **Status:** {item.get('status', 'N/A')}\n")
    if item.get("title"):
        f.write(f"- **Title:** {item['title']}\n")
    if item.get("final_url"):
        f.write(f"- **Final URL:** {item['final_url']}\n")

    _write_markdown_list(f, "Redirect Chain", item.get("redirect_chain", []))
    _write_markdown_list(f, "Missing Security Headers", _visible_missing_security_headers(item))
    _write_markdown_list(f, "Technology Hints", item.get("technology_hints", []))

    headers = item.get("headers", {})
    if headers:
        f.write("- **Response Headers:**\n")
        for key, value in sorted(headers.items()):
            f.write(f"  - `{key}`: {value}\n")


STATIC_ASSET_EXTENSIONS = {
    ".css",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
}
WELL_KNOWN_REPORT_PATHS = {
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/swagger",
    "/api-docs",
    "/ftp",
}


def _path_without_query(path):
    return str(path or "/").split("?", 1)[0].split("#", 1)[0]


def _is_api_like_endpoint(path):
    lower_path = str(path or "").lower()
    return lower_path == "/api" or lower_path == "/rest" or lower_path.startswith("/api/") or lower_path.startswith("/rest/")


def _is_static_asset(path):
    clean_path = _path_without_query(path).lower()
    filename = PurePosixPath(clean_path).name
    return PurePosixPath(clean_path).suffix in STATIC_ASSET_EXTENSIONS or "chunk" in filename


def _endpoint_category(endpoint):
    path = endpoint.get("path", "")
    lower_path = str(path).lower()
    if _is_static_asset(path):
        return "Static Assets"
    if _is_api_like_endpoint(path):
        return "API-like Endpoints"
    if lower_path in WELL_KNOWN_REPORT_PATHS:
        return "Well-known / Probed Paths"
    return "Frontend Routes"


def _endpoint_line(endpoint):
    line = (
        f"- `{endpoint.get('path', '/')}` "
        f"- **Source:** {endpoint.get('source', 'unknown')} "
        f"- **Confidence:** {endpoint.get('confidence', 'low')}"
    )
    if endpoint.get("status_code") is not None:
        line += f" - **Status:** {endpoint['status_code']}"
    if endpoint.get("content_type"):
        line += f" - **Content-Type:** {endpoint['content_type']}"
    if endpoint.get("note"):
        line += f" - **Note:** {endpoint['note']}"
    return line


def _write_endpoint_category(f, title, endpoints):
    if not endpoints:
        return
    f.write(f"#### {title}\n\n")
    if title == "Static Assets":
        f.write(f"- **Total Static Assets:** {len(endpoints)}\n")
        for endpoint in endpoints[:5]:
            f.write(f"{_endpoint_line(endpoint)}\n")
        if len(endpoints) > 5:
            f.write(f"- {len(endpoints) - 5} additional static assets omitted from Markdown.\n")
        f.write("\n")
        return

    for endpoint in endpoints[:50]:
        f.write(f"{_endpoint_line(endpoint)}\n")
    if len(endpoints) > 50:
        f.write(f"- Output trimmed. {len(endpoints) - 50} additional endpoints omitted.\n")
    f.write("\n")


def _write_endpoint_discovery(f, endpoint_results):
    f.write("## Endpoint Discovery\n\n")
    if isinstance(endpoint_results, dict) and endpoint_results.get("error"):
        f.write(f"**Error:** {endpoint_results['error']}\n")
        f.write("---\n\n")
        return

    groups = endpoint_results if isinstance(endpoint_results, list) else []
    if not groups:
        f.write("No endpoints discovered.\n")
        f.write("---\n\n")
        return

    for group in groups:
        f.write(f"### {group.get('base_url', 'Unknown base URL')}\n\n")
        endpoints = group.get("endpoints", [])
        if not endpoints:
            f.write("- No endpoints discovered.\n\n")
            continue

        categorized = {
            "API-like Endpoints": [],
            "Frontend Routes": [],
            "Well-known / Probed Paths": [],
            "Static Assets": [],
        }
        for endpoint in endpoints:
            categorized[_endpoint_category(endpoint)].append(endpoint)

        for title in ("API-like Endpoints", "Frontend Routes", "Well-known / Probed Paths", "Static Assets"):
            _write_endpoint_category(f, title, categorized[title])

    f.write("---\n\n")


def build_report_summary(results):
    nmap_results = results.get("Nmap Scan", results)
    ports = _as_list(nmap_results.get("ports", []))
    http_results = _as_list(results.get("HTTP Analysis", []))
    tls_results = _as_list(results.get("TLS Analysis", []))
    dns_results = results.get("DNS Analysis", {})
    attention_results = _as_list(results.get("Attention", []))

    dns_record_count = 0
    if isinstance(dns_results, dict):
        dns_record_count = sum(
            len(records)
            for record_type, records in dns_results.items()
            if record_type != "errors" and isinstance(records, list)
        )

    return {
        "host_status": nmap_results.get("status", {}).get("state", "Unknown"),
        "total_ports": len(ports),
        "open_ports": len([port for port in ports if port.get("state") == "open"]),
        "http_services": len(http_results),
        "tls_results": len(tls_results),
        "dns_records": dns_record_count,
        "interesting_signals": len(attention_results),
    }


def generate_report(target, results, output_file):
    """
    Generates a well-formatted Markdown report from the scan results.
    """
    logging.info(f"Generating report to: {output_file}")
    nmap_results = results.get("Nmap Scan", results)
    http_results = results.get("HTTP Analysis", [])
    endpoint_results = results.get("Endpoint Discovery")
    tls_results = results.get("TLS Analysis", [])
    dns_results = results.get("DNS Analysis", {})
    attention_results = results.get("Attention", [])
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        f.write("# Active Recon Report\n\n")
        f.write(f"**Target:** {target}\n")
        f.write(f"**Host Status:** {nmap_results.get('status', {}).get('state', 'Unknown')}\n")
        scan_context_note = _scan_context_note(target, nmap_results)
        if scan_context_note:
            f.write(f"**Scan Context:** {scan_context_note}\n")
        f.write("---\n\n")

        summary = build_report_summary(results)
        f.write("## Summary\n\n")
        f.write(f"- **Host Status:** {summary['host_status']}\n")
        f.write(f"- **Total Ports Listed:** {summary['total_ports']}\n")
        f.write(f"- **Open Ports:** {summary['open_ports']}\n")
        f.write(f"- **HTTP Services:** {summary['http_services']}\n")
        f.write(f"- **TLS Results:** {summary['tls_results']}\n")
        f.write(f"- **DNS Records:** {summary['dns_records']}\n")
        f.write(f"- **Interesting Signals:** {summary['interesting_signals']}\n")
        f.write("---\n\n")

        f.write("## Scan Information\n\n")
        f.write(_format_error(nmap_results.get("error")))
        scan_info = nmap_results.get("scan_info", {})
        f.write(f"- **Protocol:** {scan_info.get('protocol', 'N/A')}\n")
        f.write(f"- **Ports Scanned:** {scan_info.get('numservices', 'N/A')}\n")
        f.write(f"- **Host:** {nmap_results.get('host', 'Unknown')}\n")
        f.write("---\n\n")

        f.write("## Port Scan Results\n\n")
        ports = nmap_results.get("ports", [])
        if ports:
            open_ports = [port for port in ports if port.get("state") == "open"]
            other_ports = [port for port in ports if port.get("state") != "open"]
            for title, port_group in (("Open Ports", open_ports), ("Other Results", other_ports)):
                if not port_group:
                    continue
                f.write(f"### {title}\n\n")
                for port in port_group:
                    f.write(
                        f"- **Port:** {port.get('portid', 'N/A')}/{port.get('protocol', 'N/A')} "
                        f"- **State:** {port.get('state', 'unknown')} "
                        f"- **Service:** {port.get('service', 'Unknown')}\n"
                    )
                f.write("\n")
        else:
            f.write("No port scan results found.\n")
        f.write("---\n\n")

        f.write("## HTTP Analysis\n\n")
        if isinstance(http_results, dict) and http_results.get("error"):
            f.write(f"**Error:** {http_results['error']}\n")
        elif http_results:
            for item in http_results:
                f.write(f"### {item.get('url', 'Unknown URL')}\n\n")
                if item.get("error"):
                    f.write(f"- **Error:** {item['error']}\n")
                else:
                    _write_http_result(f, item)
                f.write("\n")
        else:
            f.write("No HTTP services analyzed.\n")
        f.write("---\n\n")

        if "Endpoint Discovery" in results:
            _write_endpoint_discovery(f, endpoint_results)

        f.write("## TLS Analysis\n\n")
        if isinstance(tls_results, dict) and tls_results.get("error"):
            f.write(f"**Error:** {tls_results['error']}\n")
        elif tls_results:
            for item in tls_results:
                f.write(f"### {item.get('host', 'Unknown host')}:{item.get('port', '443')}\n\n")
                if item.get("error"):
                    f.write(f"- **Error:** {item['error']}\n")
                else:
                    f.write(f"- **TLS Version:** {item.get('tls_version', 'N/A')}\n")
                    f.write(f"- **Cipher:** {item.get('cipher', 'N/A')}\n")
                    f.write(f"- **Subject:** {', '.join(item.get('subject', [])) or 'N/A'}\n")
                    f.write(f"- **Issuer:** {', '.join(item.get('issuer', [])) or 'N/A'}\n")
                    f.write(f"- **Valid From:** {item.get('not_before', 'N/A')}\n")
                    f.write(f"- **Valid Until:** {item.get('not_after', 'N/A')}\n")
                f.write("\n")
        else:
            f.write("No HTTPS services analyzed.\n")
        f.write("---\n\n")

        f.write("## DNS Analysis\n\n")
        if isinstance(dns_results, dict) and dns_results.get("error"):
            f.write(f"**Error:** {dns_results['error']}\n")
        elif isinstance(dns_results, dict) and dns_results.get("skipped"):
            f.write(f"**Skipped:** {dns_results.get('reason', 'DNS analysis skipped')}\n")
        elif dns_results:
            dns_errors = dns_results.get("errors", {})
            for record_type in ("A", "MX", "TXT"):
                records = dns_results.get(record_type, [])
                f.write(f"### {record_type} Records\n\n")
                if records:
                    for record in records:
                        f.write(f"- {record}\n")
                else:
                    f.write("- No records found.\n")
                if record_type in dns_errors:
                    f.write(f"- **Lookup Error:** {dns_errors[record_type]}\n")
                f.write("\n")
        else:
            f.write("No DNS results available.\n")
        f.write("---\n\n")

        f.write("## Interesting Signals\n\n")
        if attention_results:
            for item in attention_results:
                f.write(
                    f"- **{item.get('severity', 'info').upper()}** "
                    f"[{item.get('category', 'general')}] {item.get('message', '')}"
                )
                if item.get("evidence"):
                    f.write(f" - `{item['evidence']}`")
                f.write("\n")
        else:
            f.write("No interesting signals generated.\n")
