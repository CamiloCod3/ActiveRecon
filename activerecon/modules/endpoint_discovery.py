import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests


DEFAULT_WELL_KNOWN_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/api",
    "/rest",
    "/ftp",
    "/admin",
    "/login",
    "/debug",
    "/swagger",
    "/api-docs",
]
DEFAULT_ENDPOINT_LIMIT = 50
DEFAULT_HTTP_TIMEOUT = 5
PATH_STRING_RE = re.compile(r"""["'`](/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{1,200})["'`]""")


class EndpointHTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.links = []
        self.script_srcs = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if "href" in attrs_dict:
            self.links.append((attrs_dict["href"], "html:href"))
        if "src" in attrs_dict:
            self.links.append((attrs_dict["src"], "html:src"))
        if tag == "form" and attrs_dict.get("action"):
            self.links.append((attrs_dict["action"], "html:form-action"))
        if tag == "script" and attrs_dict.get("src"):
            self.script_srcs.append(attrs_dict["src"])


def _web_recon_settings(config):
    web_recon = config.get("web_recon", {}) if isinstance(config, dict) else {}
    return {
        "endpoint_probe_limit": web_recon.get("endpoint_probe_limit", DEFAULT_ENDPOINT_LIMIT),
        "fetch_javascript": web_recon.get("fetch_javascript", True),
        "same_origin_only": web_recon.get("same_origin_only", True),
        "well_known_paths": web_recon.get("well_known_paths", DEFAULT_WELL_KNOWN_PATHS),
    }


def _timeout(config):
    if isinstance(config, dict):
        return config.get("http_timeout", DEFAULT_HTTP_TIMEOUT)
    return DEFAULT_HTTP_TIMEOUT


def _limit(value):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return DEFAULT_ENDPOINT_LIMIT


def _is_successful_http_result(item):
    if not isinstance(item, dict) or item.get("error"):
        return False
    try:
        status = int(item.get("status", 0))
    except (TypeError, ValueError):
        return False
    return 200 <= status < 400


def _origin(url):
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _same_origin(url, base_url):
    return _origin(url) == _origin(base_url)


def _path_from_url(url):
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if parsed.fragment:
        path = f"{path}#{parsed.fragment}"
    return path


def _normalize_candidate(value, base_url, same_origin_only=True):
    if not value:
        return None

    raw_value = str(value).strip()
    if raw_value.startswith(("mailto:", "tel:", "javascript:", "data:")):
        return None

    absolute = urljoin(base_url, raw_value)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"}:
        return None
    if same_origin_only and not _same_origin(absolute, base_url):
        return None

    path = _path_from_url(absolute)
    if not path.startswith("/") or path.startswith("//"):
        return None
    return path


def _confidence(source):
    if source.startswith(("response-header", "well-known", "robots.txt", "html:")):
        return "medium"
    return "low"


def _add_endpoint(endpoints, path, source, limit, status_code=None, content_type=None):
    if not path or not path.startswith("/") or path.startswith("//") or len(path) > 250:
        return
    if path not in endpoints and len(endpoints) >= limit:
        return

    if path not in endpoints:
        endpoints[path] = {
            "path": path,
            "source": source,
            "confidence": _confidence(source),
        }

    if status_code is not None:
        endpoints[path]["status_code"] = status_code
    if content_type:
        endpoints[path]["content_type"] = content_type


def _extract_paths_from_text(text):
    paths = []
    for match in PATH_STRING_RE.finditer(text or ""):
        path = match.group(1).strip()
        if path.startswith("/") and not path.startswith("//"):
            paths.append(path)
    return paths


def _path_like_header_values(value):
    values = value if isinstance(value, (list, tuple, set)) else [value]
    paths = []
    for raw_value in values:
        for candidate in str(raw_value).split(","):
            path = candidate.strip().strip("\"'")
            if path.startswith("/") and not path.startswith("//") and len(path) > 1:
                paths.append(path)
    return paths


def _safe_get(url, timeout):
    try:
        return requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        logging.debug(f"Endpoint discovery request failed for {url}: {e}")
        return None


def _content_type(response):
    return response.headers.get("Content-Type") or response.headers.get("content-type") or ""


def _is_found_probe(response):
    if response is None:
        return False
    return response.status_code < 400 or response.status_code in {401, 403}


def _robots_disallow_paths(text):
    paths = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("disallow:"):
            continue
        path = stripped.split(":", 1)[1].strip()
        if path.startswith("/") and not path.startswith("//"):
            paths.append(path)
    return paths


def _parse_html(text):
    parser = EndpointHTMLParser()
    try:
        parser.feed(text or "")
    except Exception as e:
        logging.debug(f"Endpoint discovery HTML parsing failed: {e}")
    return parser


def discover_endpoints(http_results, config=None):
    """
    Discover a small set of interesting endpoints from HTTP results.
    This intentionally avoids aggressive directory brute forcing.
    """
    if not isinstance(http_results, list):
        return []

    settings = _web_recon_settings(config or {})
    endpoint_limit = _limit(settings["endpoint_probe_limit"])
    timeout = _timeout(config)
    same_origin_only = bool(settings["same_origin_only"])
    fetch_javascript = bool(settings["fetch_javascript"])
    well_known_paths = settings["well_known_paths"] or DEFAULT_WELL_KNOWN_PATHS
    groups = []

    for item in http_results:
        if not _is_successful_http_result(item):
            continue

        base_url = item.get("final_url") or item.get("url")
        if not base_url:
            continue
        base_origin = _origin(base_url)
        if not base_origin:
            continue

        endpoints = {}
        requests_made = 0

        def get_if_allowed(url):
            nonlocal requests_made
            if requests_made >= endpoint_limit:
                return None
            requests_made += 1
            return _safe_get(url, timeout)

        for header_name, header_value in (item.get("headers") or {}).items():
            for path in _path_like_header_values(header_value):
                _add_endpoint(endpoints, path, f"response-header:{header_name}", endpoint_limit)

        page_response = get_if_allowed(base_url)
        if page_response is not None and page_response.status_code < 400 and "html" in _content_type(page_response).lower():
            html_text = getattr(page_response, "text", "")[:200000]
            parser = _parse_html(html_text)
            for raw_link, source in parser.links:
                path = _normalize_candidate(raw_link, base_url, same_origin_only)
                if path:
                    _add_endpoint(endpoints, path, source, endpoint_limit)
            for path in _extract_paths_from_text(html_text):
                _add_endpoint(endpoints, path, "html-string", endpoint_limit)

            if fetch_javascript:
                for script_src in parser.script_srcs:
                    script_url = urljoin(base_url, script_src)
                    if same_origin_only and not _same_origin(script_url, base_url):
                        continue
                    script_response = get_if_allowed(script_url)
                    if script_response is None or script_response.status_code >= 400:
                        continue
                    script_text = getattr(script_response, "text", "")[:200000]
                    for path in _extract_paths_from_text(script_text):
                        _add_endpoint(endpoints, path, "javascript", endpoint_limit)

        for path in well_known_paths[:endpoint_limit]:
            if not str(path).startswith("/"):
                continue
            response = get_if_allowed(urljoin(base_origin, path))
            if not _is_found_probe(response):
                continue
            _add_endpoint(
                endpoints,
                path,
                "well-known",
                endpoint_limit,
                status_code=response.status_code,
                content_type=_content_type(response),
            )
            if path == "/robots.txt" and response.status_code < 400:
                for disallow_path in _robots_disallow_paths(getattr(response, "text", "")):
                    _add_endpoint(endpoints, disallow_path, "robots.txt", endpoint_limit)

        if endpoints:
            groups.append({
                "base_url": base_origin,
                "endpoints": list(endpoints.values()),
            })

    return groups
