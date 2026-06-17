import ipaddress
from urllib.parse import urlparse

from ..models import TargetSpec


def parse_target(value):
    raw = str(value or "").strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or raw).strip().rstrip(".").lower()
    path = parsed.path or ""

    port = None
    try:
        port = parsed.port
    except ValueError:
        port = None

    is_ip = False
    is_private = False
    is_loopback = False
    if host == "localhost":
        is_private = True
        is_loopback = True
    try:
        address = ipaddress.ip_address(host)
        is_ip = True
        is_private = address.is_private
        is_loopback = address.is_loopback
    except ValueError:
        pass

    return TargetSpec(
        raw=raw,
        host=host,
        scheme=parsed.scheme or None,
        port=port,
        path=path,
        is_ip=is_ip,
        is_private=is_private,
        is_loopback=is_loopback,
    )
