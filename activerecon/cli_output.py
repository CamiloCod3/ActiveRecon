from .modules.json_report import build_json_summary


def _dns_summary(result, summary):
    dns_results = result.results.get("DNS Analysis", {})
    if isinstance(dns_results, dict) and dns_results.get("skipped"):
        return "skipped for IP target"
    return f"{summary['dns_records']} records"


def _endpoint_count(result, summary):
    if "Endpoint Discovery" not in result.results:
        return None
    return summary["endpoint_count"]


def _report_paths(result):
    paths = []
    if result.markdown_output:
        paths.append(("Markdown", result.markdown_output))
    if result.json_output:
        paths.append(("JSON", result.json_output))
    return paths


def print_report_paths(result, output=print):
    paths = _report_paths(result)
    if not paths:
        return
    for label, path in paths:
        output(f"{label}: {path}")


def print_scan_summary(result, output=print):
    summary = build_json_summary(result.results)
    endpoint_count = _endpoint_count(result, summary)

    title = "ActiveRecon dry run completed" if result.dry_run else "ActiveRecon scan completed"
    output(title)
    output("")
    output(f"Target: {result.target}")
    output(f"Profile: {result.scan_profile}")
    output("")

    if result.dry_run:
        output("No scan executed.")
    else:
        output(f"Nmap: {summary['total_ports_listed']} ports listed, {summary['open_ports']} open")
        output(f"HTTP: {summary['http_services']} service analyzed")
        output(f"TLS: {summary['tls_results']} HTTPS services analyzed")
        output(f"DNS: {_dns_summary(result, summary)}")
        if endpoint_count is not None:
            output(f"Endpoints: {endpoint_count} discovered")
        output(f"Interesting Signals: {summary['interesting_signals']}")

    paths = _report_paths(result)
    if paths:
        output("")
        output("Reports:")
        for label, path in paths:
            output(f"- {label}: {path}")
