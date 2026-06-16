import dns.resolver

from activerecon.modules.dns_analysis import analyze_dns


class AAnswer:
    address = "192.0.2.10"


class Exchange:
    def to_text(self):
        return "mail.example.com."


class MXAnswer:
    exchange = Exchange()


class TXTAnswer:
    def to_text(self):
        return '"v=spf1 -all"'


def test_analyze_dns_resolves_record_types_independently(monkeypatch):
    def fake_resolve(target, record_type):
        if record_type == "A":
            return [AAnswer()]
        if record_type == "MX":
            raise dns.resolver.NoAnswer()
        return [TXTAnswer()]

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    result = analyze_dns("example.com")

    assert result["A"] == ["192.0.2.10"]
    assert result["MX"] == []
    assert result["TXT"] == ['"v=spf1 -all"']
    assert "MX" in result["errors"]


def test_analyze_dns_reads_mx_exchange(monkeypatch):
    def fake_resolve(target, record_type):
        if record_type == "MX":
            return [MXAnswer()]
        return []

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    result = analyze_dns("example.com")

    assert result["MX"] == ["mail.example.com."]
