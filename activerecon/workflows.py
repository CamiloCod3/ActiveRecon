COMMON_HTTP_PORTS = {"80", "443", "3000", "5000", "8000", "8080", "8443", "9000", "9443"}


def is_http_service(port):
    service = str(port.get("service", "")).lower()
    state = str(port.get("state", "")).lower()
    portid = str(port.get("portid", ""))

    if state and state != "open":
        return False

    return "http" in service or portid in COMMON_HTTP_PORTS


def get_http_ports(nmap_results):
    ports = nmap_results.get("ports", []) if isinstance(nmap_results, dict) else []
    return [port for port in ports if is_http_service(port)]


def web_recon_enabled(config, scan_profile):
    web_recon = config.get("web_recon", {}) if isinstance(config, dict) else {}
    enabled_profiles = web_recon.get("enabled_profiles", [])
    return scan_profile in enabled_profiles
