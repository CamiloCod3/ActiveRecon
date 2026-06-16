import subprocess

from activerecon.modules.nmap_scan import run_nmap_scan


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="syn" protocol="tcp" numservices="100"/>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_run_nmap_scan_parses_successful_xml(monkeypatch):
    def fake_run(command, stdout, stderr, text, check):
        assert command == ["nmap", "-Pn", "-oX", "-", "127.0.0.1"]
        return subprocess.CompletedProcess(command, 0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_nmap_scan("127.0.0.1", "-Pn")

    assert result["status"]["state"] == "up"
    assert result["scan_info"]["protocol"] == "tcp"
    assert result["host"] == "127.0.0.1"
    assert result["ports"] == [{
        "portid": "80",
        "protocol": "tcp",
        "state": "open",
        "service": "http",
    }]


def test_run_nmap_scan_handles_empty_output(monkeypatch):
    def fake_run(command, stdout, stderr, text, check):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="permission denied")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_nmap_scan("example.com", "-sS")

    assert result["ports"] == []
    assert result["error"] == "permission denied"


def test_run_nmap_scan_handles_none_output(monkeypatch):
    def fake_run(command, stdout, stderr, text, check):
        return subprocess.CompletedProcess(command, 1, stdout=None, stderr=None)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_nmap_scan("example.com", "-sS")

    assert result["ports"] == []
    assert result["error"] == "Nmap did not return XML output"


def test_run_nmap_scan_handles_invalid_xml(monkeypatch):
    def fake_run(command, stdout, stderr, text, check):
        return subprocess.CompletedProcess(command, 0, stdout="<nmaprun>", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_nmap_scan("example.com", "-sS")

    assert result["ports"] == []
    assert "Failed to parse Nmap XML output" in result["error"]


def test_run_nmap_scan_handles_missing_nodes(monkeypatch):
    def fake_run(command, stdout, stderr, text, check):
        return subprocess.CompletedProcess(command, 0, stdout="<nmaprun><host /></nmaprun>", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = run_nmap_scan("example.com", "-sS")

    assert result["status"] == {"state": "unknown"}
    assert result["scan_info"] == {}
    assert result["host"] == "Unknown"
    assert result["ports"] == []
