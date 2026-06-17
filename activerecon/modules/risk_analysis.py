from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS header",
    "content-security-policy": "Missing Content-Security-Policy header",
    "x-frame-options": "Missing X-Frame-Options header",
    "x-content-type-options": "Missing X-Content-Type-Options header",
}
COMMON_HTTP_PORTS = {"80", "443", "3000", "5000", "8000", "8080", "8443", "9000", "9443"}


def _finding(severity, category, message, evidence=None):
    return {
        "severity": severity,
        "category": category,
        "message": message,
        "evidence": evidence or "",
    }


def _open_ports(results):
    nmap_results = results.get("Nmap Scan", {})
    ports = nmap_results.get("ports", [])
    if not isinstance(ports, list):
        return []
    return [
        port
        for port in ports
        if isinstance(port, dict) and str(port.get("state", "")).lower() == "open"
    ]


def _http_results(results):
    http_results = results.get("HTTP Analysis", [])
    return http_results if isinstance(http_results, list) else []


def _tls_results(results):
    tls_results = results.get("TLS Analysis", [])
    return tls_results if isinstance(tls_results, list) else []


def _dns_results(results):
    dns_results = results.get("DNS Analysis", {})
    return dns_results if isinstance(dns_results, dict) else {}


def generate_attention_findings(results, now=None):
    findings = []

    for port in _open_ports(results):
        service = str(port.get("service", "")).lower()
        portid = str(port.get("portid", ""))
        if portid in {"21", "23", "3389"}:
            findings.append(_finding("medium", "exposure", f"Sensitive remote access service exposed on port {portid}", service))
        elif portid in COMMON_HTTP_PORTS or "http" in service:
            findings.append(_finding("info", "http", f"HTTP service detected on port {portid}", service))

    for item in _http_results(results):
        if item.get("error"):
            findings.append(_finding("low", "http", "HTTP analysis failed for a detected service", item.get("url", "")))
            continue
        for header_name, message in SECURITY_HEADERS.items():
            if header_name in item.get("missing_security_headers", []):
                findings.append(_finding("low", "http", message, item.get("url", "")))
        if item.get("redirect_chain"):
            findings.append(_finding("info", "http", "HTTP redirects observed", " -> ".join(item["redirect_chain"])))

    now = now or datetime.now(timezone.utc)
    comparable_now = now.replace(tzinfo=None)
    for item in _tls_results(results):
        if item.get("error"):
            findings.append(_finding("low", "tls", "TLS analysis failed for an HTTPS service", item.get("url", "")))
            continue
        not_after = item.get("not_after")
        if not_after:
            try:
                expires_at = parsedate_to_datetime(not_after)
                if expires_at.replace(tzinfo=None) < comparable_now:
                    findings.append(_finding("high", "tls", "TLS certificate is expired", item.get("url", "")))
            except (TypeError, ValueError):
                findings.append(_finding("low", "tls", "TLS certificate expiry could not be parsed", item.get("url", "")))

    dns_errors = _dns_results(results).get("errors", {})
    for record_type in sorted(dns_errors):
        findings.append(_finding("info", "dns", f"DNS {record_type} lookup returned no usable result", dns_errors[record_type]))

    return findings
