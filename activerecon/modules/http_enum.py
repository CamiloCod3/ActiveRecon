import logging

import requests


DEFAULT_HTTP_TIMEOUT = 5

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
            results.append({
                "url": url,
                "port": portid,
                "service": service or scheme,
                "status": response.status_code,
                "headers": dict(response.headers),
            })
        except requests.RequestException as e:
            results.append({"url": url, "port": portid, "service": service or scheme, "error": str(e)})

    logging.info("HTTP analysis completed.")
    return results
