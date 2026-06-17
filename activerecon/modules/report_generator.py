import logging
from pathlib import Path


def _format_error(error):
    return f"\n**Error:** {error}\n" if error else ""


def _as_list(value):
    return value if isinstance(value, list) else []


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
    tls_results = results.get("TLS Analysis", [])
    dns_results = results.get("DNS Analysis", {})
    attention_results = results.get("Attention", [])
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        f.write("# Active Recon Report\n\n")
        f.write(f"**Target:** {target}\n")
        f.write(f"**Host Status:** {nmap_results.get('status', {}).get('state', 'Unknown')}\n")
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

        f.write("## Open Ports\n\n")
        ports = nmap_results.get("ports", [])
        if ports:
            for port in ports:
                f.write(
                    f"- **Port:** {port.get('portid', 'N/A')}/{port.get('protocol', 'N/A')} "
                    f"- **State:** {port.get('state', 'unknown')} "
                    f"- **Service:** {port.get('service', 'Unknown')}\n"
                )
        else:
            f.write("No open ports found.\n")
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
                    f.write(f"- **Status:** {item.get('status', 'N/A')}\n")
                    headers = item.get("headers", {})
                    if headers:
                        f.write("- **Headers:**\n")
                        for key, value in sorted(headers.items()):
                            f.write(f"  - `{key}`: {value}\n")
                f.write("\n")
        else:
            f.write("No HTTP services analyzed.\n")
        f.write("---\n\n")

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
