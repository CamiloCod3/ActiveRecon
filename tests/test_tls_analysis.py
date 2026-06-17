import socket
import ssl

from activerecon.modules.tls_analysis import analyze_tls


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class FakeTlsSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def getpeercert(self):
        return {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


class FakeContext:
    def wrap_socket(self, sock, server_hostname):
        assert server_hostname == "example.com"
        return FakeTlsSocket()


def test_analyze_tls_collects_certificate_metadata(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: FakeSocket())
    monkeypatch.setattr(ssl, "create_default_context", lambda: FakeContext())

    result = analyze_tls([{"url": "https://example.com:443", "final_url": "https://example.com:443"}])

    assert result[0]["host"] == "example.com"
    assert result[0]["tls_version"] == "TLSv1.3"
    assert result[0]["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result[0]["subject"] == ["example.com"]
    assert result[0]["subject_alt_names"] == ["example.com"]


def test_analyze_tls_records_connection_errors(monkeypatch):
    def fake_connection(address, timeout):
        raise OSError("connection failed")

    monkeypatch.setattr(socket, "create_connection", fake_connection)

    result = analyze_tls([{"url": "https://example.com:443"}])

    assert result[0]["host"] == "example.com"
    assert "connection failed" in result[0]["error"]


def test_analyze_tls_skips_non_https_services():
    assert analyze_tls([{"url": "http://example.com:80"}]) == []
