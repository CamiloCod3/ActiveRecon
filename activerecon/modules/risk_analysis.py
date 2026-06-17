from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS header",
    "content-security-policy": "Missing Content-Security-Policy header",
    "x-frame-options": "Missing X-Frame-Options header",
    "x-content-type-options": "Missing X-Content-Type-Options header",
}
COMMON_HTTP_PORTS = {"80", "443", "3000", "5000", "8000", "8080", "8443", "9000", "9443"}
WILDCARD_CORS_HEADER = "access-control-allow-origin"
X_POWERED_BY_HEADER = "x-powered-by"


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


def _endpoint_groups(results):
    endpoint_results = results.get("Endpoint Discovery", [])
    return endpoint_results if isinstance(endpoint_results, list) else []


def _endpoint_items(results):
    for group in _endpoint_groups(results):
        base_url = group.get("base_url", "")
        for endpoint in group.get("endpoints", []):
            if isinstance(endpoint, dict):
                yield base_url, endpoint


def _is_https_result(item):
    url = str(item.get("final_url") or item.get("url") or "").lower()
    return url.startswith("https://")


def _response_headers(item):
    headers = item.get("headers", {})
    return headers if isinstance(headers, dict) else {}


def _first_path_like_header_value(value):
    values = value if isinstance(value, (list, tuple, set)) else [value]
    for raw_value in values:
        for candidate in str(raw_value).split(","):
            path = candidate.strip().strip("\"'")
            if path.startswith("/") and len(path) > 1:
                return path
    return None


def _header_value_text(value):
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item).strip() for item in value if str(item).strip())
    return str(value).strip()


def _is_api_like_path(path):
    lower_path = str(path).lower()
    return lower_path == "/api" or lower_path == "/rest" or lower_path.startswith("/api/") or lower_path.startswith("/rest/")


def _is_admin_debug_docs_path(path):
    lower_path = str(path).lower()
    return any(token in lower_path for token in ("/admin", "/debug", "/swagger", "/api-docs"))


def _url_origin(url):
    parsed = urlparse(str(url or ""))
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _endpoint_evidence(base_url, path):
    if not base_url:
        return str(path or "")
    if not path:
        return str(base_url)
    return f"{str(base_url).rstrip('/')}/{str(path).lstrip('/')}"


def _http_header_path_evidence(item, path):
    origin = _url_origin(item.get("final_url") or item.get("url"))
    return _endpoint_evidence(origin, path) if origin else str(path or "")


def _header_name_from_source(source):
    prefix, separator, header_name = str(source or "").partition(":")
    if prefix == "response-header" and separator and header_name:
        return header_name
    return "response header"


def generate_attention_findings(results, now=None):
    findings = []
    seen_endpoint_signals = set()

    def add_endpoint_signal(severity, category, message, evidence):
        key = (category, message, evidence)
        if key in seen_endpoint_signals:
            return
        seen_endpoint_signals.add(key)
        findings.append(_finding(severity, category, message, evidence))

    for port in _open_ports(results):
        service = str(port.get("service", "")).lower()
        portid = str(port.get("portid", ""))
        if portid in {"21", "23", "3389"}:
            findings.append(_finding("medium", "exposure", f"Sensitive remote access service exposed on port {portid}", service))
        elif portid == "445":
            findings.append(_finding("medium", "exposure", "SMB service exposed on port 445", service))
        elif portid == "135":
            findings.append(_finding("info", "exposure", "RPC endpoint mapper observed on port 135", service))
        elif portid in COMMON_HTTP_PORTS or "http" in service:
            findings.append(_finding("info", "http", f"HTTP service detected on port {portid}", service))

    for item in _http_results(results):
        if item.get("error"):
            findings.append(_finding("low", "http", "HTTP analysis failed for a detected service", item.get("url", "")))
            continue
        for header_name, message in SECURITY_HEADERS.items():
            if header_name == "strict-transport-security" and not _is_https_result(item):
                continue
            if header_name in item.get("missing_security_headers", []):
                findings.append(_finding("low", "http", message, item.get("url", "")))

        for header_name, value in _response_headers(item).items():
            normalized_header = str(header_name).lower()
            header_value = _header_value_text(value)
            if normalized_header == WILDCARD_CORS_HEADER and header_value == "*":
                findings.append(_finding("info", "cors", "Wildcard CORS header observed", item.get("url", "")))
            if normalized_header == X_POWERED_BY_HEADER and header_value:
                evidence = f"{header_value} - {item.get('url', '')}".strip(" -")
                findings.append(_finding("info", "technology", "X-Powered-By header exposed", evidence))

            path = _first_path_like_header_value(value)
            if path:
                add_endpoint_signal(
                    "info",
                    "endpoint",
                    f"Interesting path found in response header {header_name}",
                    _http_header_path_evidence(item, path),
                )

        if item.get("redirect_chain"):
            findings.append(_finding("info", "http", "HTTP redirects observed", " -> ".join(item["redirect_chain"])))

    for base_url, endpoint in _endpoint_items(results):
        path = endpoint.get("path", "")
        source = endpoint.get("source", "")
        evidence = _endpoint_evidence(base_url, path)

        if path == "/robots.txt" and endpoint.get("status_code") is not None:
            add_endpoint_signal("info", "endpoint", "robots.txt found; follow-up recommended", evidence)
        if source == "robots.txt":
            add_endpoint_signal("info", "endpoint", "robots.txt contains Disallow paths; follow-up recommended", evidence)
        if source.startswith("response-header"):
            header_name = _header_name_from_source(source)
            add_endpoint_signal(
                "info",
                "endpoint",
                f"Interesting path found in response header {header_name}",
                evidence,
            )
        if _is_api_like_path(path):
            if source.startswith("javascript"):
                add_endpoint_signal("info", "endpoint", "JavaScript exposes API-like path candidate", evidence)
            else:
                add_endpoint_signal("info", "endpoint", "API-like endpoint discovered; follow-up recommended", evidence)
        if _is_admin_debug_docs_path(path):
            add_endpoint_signal("info", "endpoint", "Possible admin/debug/docs route discovered; follow-up recommended", evidence)
        if str(path).lower() == "/ftp":
            add_endpoint_signal("info", "endpoint", "/ftp endpoint discovered; follow-up recommended", evidence)

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
