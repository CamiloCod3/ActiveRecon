from activerecon.workflows import is_http_service


def test_is_http_service_detects_open_dev_port():
    assert is_http_service({"portid": "3000", "state": "open", "service": "ppp"})
    assert not is_http_service({"portid": "3000", "state": "closed", "service": "ppp"})
    assert not is_http_service({"portid": "8080", "state": "filtered", "service": "http"})
