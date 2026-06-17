import logging
import re

import requests


DEFAULT_HTTP_TIMEOUT = 5
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
]


def _response_title(response):
    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        return None

    match = re.search(r"<title[^>]*>(.*?)</title>", getattr(response, "text", "")[:8192], flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None

    return re.sub(r"\s+", " ", match.group(1)).strip()


def _security_headers(headers):
    normalized = {key.lower(): value for key, value in headers.items()}
    present = {header: normalized[header] for header in SECURITY_HEADERS if header in normalized}
    missing = [header for header in SECURITY_HEADERS if header not in normalized]
    return present, missing


def _technology_hints(headers):
    hints = []
    server = headers.get("Server") or headers.get("server")
    powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")

    if server:
        hints.append(f"server:{server}")
    if powered_by:
        hints.append(f"x-powered-by:{powered_by}")

    return hints

def _get_timeout(config):
    if isinstance(config, dict):
        return config.get("http_timeout", DEFAULT_HTTP_TIMEOUT)
    return DEFAULT_HTTP_TIMEOUT


def _normalize_port(port):
    if isinstance(port, dict):
        portid = str(port.get("portid", "")).strip()
        service = str(port.get("service", "")).lower()
    else:
        portid = str(port).strip()
        service = ""

    scheme = "https" if "https" in service or "ssl" in service or portid in {"443", "8443"} else "http"
    return portid, service, scheme


def analyze_http(target, config, http_ports):
    """
    Analyzes HTTP services and returns headers and status codes.
    """
    logging.info("Starting HTTP analysis")
    results = []
    timeout = _get_timeout(config)

    for port in http_ports or []:
        portid, service, scheme = _normalize_port(port)
        if not portid:
            results.append({"port": portid, "error": "Missing HTTP port"})
            continue

        url = f"{scheme}://{target}:{portid}"
        try:
            response = requests.get(url, timeout=timeout)
            headers = dict(response.headers)
            present_headers, missing_headers = _security_headers(headers)
            results.append({
                "url": url,
                "final_url": getattr(response, "url", url),
                "port": portid,
                "service": service or scheme,
                "status": response.status_code,
                "title": _response_title(response),
                "redirect_chain": [history.url for history in getattr(response, "history", [])],
                "headers": headers,
                "security_headers": present_headers,
                "missing_security_headers": missing_headers,
                "technology_hints": _technology_hints(headers),
            })
        except requests.RequestException as e:
            results.append({"url": url, "port": portid, "service": service or scheme, "error": str(e)})

    logging.info("HTTP analysis completed.")
    return results
