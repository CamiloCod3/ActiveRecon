from activerecon.modules.endpoint_categories import categorize_endpoints, endpoint_category_summary


def test_endpoint_categories_group_common_endpoint_types():
    endpoints = [
        {"path": "/api", "source": "well-known"},
        {"path": "/login", "source": "html:href"},
        {"path": "/app.js", "source": "html:script-src"},
        {"path": "/robots.txt", "source": "well-known"},
        {"path": "/#/jobs", "source": "response-header:X-Recruiting"},
        {"path": "/socket.io/?EIO=4", "source": "javascript"},
        {"path": "/api", "source": "javascript"},
    ]

    categories = categorize_endpoints(endpoints)
    summary = endpoint_category_summary(endpoints, categories)

    assert [item["path"] for item in categories["api_like"]] == ["/api", "/api"]
    assert categories["frontend_routes"][0]["path"] == "/login"
    assert categories["static_assets"][0]["path"] == "/app.js"
    assert categories["well_known"][0]["path"] == "/robots.txt"
    assert categories["header_discovered"][0]["path"] == "/#/jobs"
    assert categories["realtime_services"][0]["path"] == "/socket.io/?EIO=4"
    assert summary["endpoint_count"] == 6
    assert summary["api_like"] == 1
