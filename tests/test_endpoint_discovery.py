from activerecon.modules import endpoint_discovery


class Response:
    def __init__(self, status_code=200, headers=None, text="", url="http://example.com:3000"):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.url = url


def test_discover_endpoints_extracts_html_js_headers_and_safe_probes(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append((url, timeout))
        if url == "http://example.com:3000":
            return Response(
                headers={"Content-Type": "text/html"},
                text="""
                    <title>Juice Shop</title>
                    <a href="/login">login</a>
                    <link rel="stylesheet" href="/style.css">
                    <link rel="icon" href="/favicon.ico">
                    <form action="/submit"></form>
                    <script src="/app.js"></script>
                    <script>fetch("/rest/products")</script>
                    <script src="https://cdn.example.net/external.js"></script>
                """,
                url=url,
            )
        if url == "http://example.com:3000/app.js":
            return Response(headers={"Content-Type": "application/javascript"}, text='const api = "/api/orders";', url=url)
        if url == "http://example.com:3000/robots.txt":
            return Response(headers={"Content-Type": "text/plain"}, text="Disallow: /hidden\n", url=url)
        if url == "http://example.com:3000/api":
            return Response(headers={"Content-Type": "application/json"}, text="{}", url=url)
        if url == "http://example.com:3000/admin":
            return Response(
                status_code=200,
                headers={"Content-Type": "text/html"},
                text="<title>Juice Shop</title><main></main>",
                url=url,
            )
        return Response(status_code=404, headers={"Content-Type": "text/plain"}, text="", url=url)

    monkeypatch.setattr(endpoint_discovery.requests, "get", fake_get)

    results = endpoint_discovery.discover_endpoints(
        [{
            "url": "http://example.com:3000",
            "final_url": "http://example.com:3000",
            "status": 200,
            "headers": {"X-Recruiting": "/#/jobs"},
        }],
        {
            "http_timeout": 2,
            "web_recon": {
                "endpoint_probe_limit": 20,
                "fetch_javascript": True,
                "same_origin_only": True,
                "well_known_paths": ["/robots.txt", "/api", "/admin"],
            },
        },
    )

    endpoints = {item["path"]: item for item in results[0]["endpoints"]}

    assert results[0]["base_url"] == "http://example.com:3000"
    assert endpoints["/#/jobs"]["source"] == "response-header:X-Recruiting"
    assert endpoints["/login"]["source"] == "html:href"
    assert endpoints["/style.css"]["source"] == "html:stylesheet"
    assert endpoints["/favicon.ico"]["source"] == "html:icon"
    assert endpoints["/app.js"]["source"] == "html:script-src"
    assert endpoints["/submit"]["source"] == "html:form-action"
    assert endpoints["/rest/products"]["source"] == "html-string"
    assert endpoints["/api/orders"]["source"] == "javascript"
    assert endpoints["/robots.txt"]["status_code"] == 200
    assert endpoints["/robots.txt"]["content_type"] == "text/plain"
    assert endpoints["/hidden"]["source"] == "robots.txt"
    assert endpoints["/api"]["status_code"] == 200
    assert endpoints["/admin"]["status_code"] == 200
    assert endpoints["/admin"]["note"] == "Possible SPA fallback route"
    assert not any("cdn.example.net" in url for url, timeout in calls)


def test_discover_endpoints_skips_unsuccessful_http_results(monkeypatch):
    monkeypatch.setattr(
        endpoint_discovery.requests,
        "get",
        lambda url, timeout: (_ for _ in ()).throw(AssertionError("No requests expected")),
    )

    results = endpoint_discovery.discover_endpoints(
        [
            {"url": "http://example.com", "status": 500, "headers": {}},
            {"url": "http://example.com", "status": 200, "error": "timeout"},
        ],
        {"web_recon": {"endpoint_probe_limit": 5}},
    )

    assert results == []
