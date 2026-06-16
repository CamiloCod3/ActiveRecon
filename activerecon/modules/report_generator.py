import logging


def _format_error(error):
    return f"\n**Error:** {error}\n" if error else ""


def generate_report(target, results, output_file):
    """
    Generates a well-formatted Markdown report from the scan results.
    """
    logging.info(f"Generating report to: {output_file}")
    nmap_results = results.get("Nmap Scan", results)
    http_results = results.get("HTTP Analysis", [])
    dns_results = results.get("DNS Analysis", {})

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Active Recon Report\n\n")
        f.write(f"**Target:** {target}\n")
        f.write(f"**Host Status:** {nmap_results.get('status', {}).get('state', 'Unknown')}\n")
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

        f.write("## DNS Analysis\n\n")
        if isinstance(dns_results, dict) and dns_results.get("error"):
            f.write(f"**Error:** {dns_results['error']}\n")
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
