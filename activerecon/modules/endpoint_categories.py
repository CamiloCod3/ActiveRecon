from pathlib import PurePosixPath


STATIC_ASSET_EXTENSIONS = {
    ".css",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
}
WELL_KNOWN_PATHS = {
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/swagger",
    "/api-docs",
    "/ftp",
}
CATEGORY_KEYS = (
    "api_like",
    "frontend_routes",
    "static_assets",
    "well_known",
    "header_discovered",
    "realtime_services",
)
MARKDOWN_CATEGORY_TITLES = {
    "api_like": "API-like Endpoints",
    "frontend_routes": "Frontend Routes",
    "realtime_services": "Realtime / Service Endpoints",
    "well_known": "Well-known / Probed Paths",
    "static_assets": "Static Assets",
}
MARKDOWN_CATEGORY_ORDER = (
    "api_like",
    "frontend_routes",
    "realtime_services",
    "well_known",
    "static_assets",
)


def path_without_query(path):
    return str(path or "/").split("?", 1)[0].split("#", 1)[0]


def is_api_like(path):
    lower_path = str(path or "").lower()
    return (
        lower_path == "/api"
        or lower_path == "/rest"
        or lower_path.startswith("/api/")
        or lower_path.startswith("/rest/")
    )


def is_static_asset(path):
    clean_path = path_without_query(path).lower()
    filename = PurePosixPath(clean_path).name
    return PurePosixPath(clean_path).suffix in STATIC_ASSET_EXTENSIONS or "chunk" in filename


def is_realtime_service(path):
    clean_path = path_without_query(path).lower().rstrip("/")
    return (
        clean_path == "/socket.io"
        or clean_path == "/engine.io"
        or clean_path.startswith(("/socket.io/", "/engine.io/"))
    )


def unique_endpoint_paths(endpoints):
    return {
        endpoint.get("path")
        for endpoint in endpoints
        if isinstance(endpoint, dict) and endpoint.get("path")
    }


def primary_endpoint_category(endpoint):
    path = endpoint.get("path", "")
    lower_path = path_without_query(path).lower()
    if is_realtime_service(path):
        return "realtime_services"
    if is_static_asset(path):
        return "static_assets"
    if is_api_like(path):
        return "api_like"
    if lower_path in WELL_KNOWN_PATHS:
        return "well_known"
    return "frontend_routes"


def categorize_endpoints(endpoints):
    categories = {key: [] for key in CATEGORY_KEYS}
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        categories[primary_endpoint_category(endpoint)].append(endpoint)
        if str(endpoint.get("source", "")).startswith("response-header"):
            categories["header_discovered"].append(endpoint)
    return categories


def endpoint_category_summary(endpoints, categories=None):
    categories = categories or categorize_endpoints(endpoints)
    summary = {"endpoint_count": len(unique_endpoint_paths(endpoints))}
    for key in CATEGORY_KEYS:
        summary[key] = len(unique_endpoint_paths(categories[key]))
    return summary
