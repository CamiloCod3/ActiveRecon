import logging
import socket
import ssl
from urllib.parse import urlparse


def _https_targets(http_results):
    targets = []
    for item in http_results or []:
        url = item.get("final_url") or item.get("url", "")
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            continue
        targets.append({
            "url": url,
            "host": parsed.hostname,
            "port": parsed.port or 443,
        })
    return targets


def _cert_names(cert, field_name):
    names = []
    for group in cert.get(field_name, ()):
        for key, value in group:
            if key == "commonName":
                names.append(value)
    return names


def _subject_alt_names(cert):
    return [
        value
        for key, value in cert.get("subjectAltName", ())
        if key.lower() == "dns"
    ]


def analyze_tls(http_results, timeout=5):
    logging.info("Starting TLS analysis")
    results = []

    for target in _https_targets(http_results):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((target["host"], target["port"]), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target["host"]) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
                    results.append({
                        "url": target["url"],
                        "host": target["host"],
                        "port": target["port"],
                        "tls_version": tls_sock.version(),
                        "cipher": cipher[0] if cipher else None,
                        "subject": _cert_names(cert, "subject"),
                        "issuer": _cert_names(cert, "issuer"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subject_alt_names": _subject_alt_names(cert),
                    })
        except (OSError, ssl.SSLError) as e:
            results.append({
                "url": target["url"],
                "host": target["host"],
                "port": target["port"],
                "error": str(e),
            })

    logging.info("TLS analysis completed.")
    return results
