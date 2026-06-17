import subprocess

from activerecon.modules import nmap_scan


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


def _force_nmap(monkeypatch, path="nmap"):
    monkeypatch.setattr(nmap_scan, "resolve_nmap_executable", lambda config=None: path)


def test_resolve_nmap_executable_prefers_configured_path(monkeypatch, tmp_path):
    executable = tmp_path / "nmap.exe"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr(nmap_scan.shutil, "which", lambda name: None)

    assert nmap_scan.resolve_nmap_executable({"nmap_executable": str(executable)}) == str(executable)


def test_resolve_nmap_executable_uses_path(monkeypatch):
    monkeypatch.setattr(nmap_scan.shutil, "which", lambda name: "C:\\Tools\\Nmap\\nmap.exe")
    monkeypatch.setattr(nmap_scan, "WINDOWS_NMAP_PATHS", [])

    assert nmap_scan.resolve_nmap_executable() == "C:\\Tools\\Nmap\\nmap.exe"


def test_resolve_nmap_executable_uses_common_windows_paths(monkeypatch, tmp_path):
    executable = tmp_path / "nmap.exe"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr(nmap_scan.shutil, "which", lambda name: None)
    monkeypatch.setattr(nmap_scan, "WINDOWS_NMAP_PATHS", [str(executable)])

    assert nmap_scan.resolve_nmap_executable() == str(executable)


def test_run_nmap_scan_returns_error_when_nmap_is_missing(monkeypatch):
    monkeypatch.setattr(nmap_scan.shutil, "which", lambda name: None)
    monkeypatch.setattr(nmap_scan, "WINDOWS_NMAP_PATHS", [])

    result = nmap_scan.run_nmap_scan("example.com", "-sS")

    assert result["ports"] == []
    assert result["error"] == "Nmap executable was not found"


def test_run_nmap_scan_parses_successful_xml(monkeypatch):
    _force_nmap(monkeypatch)

    def fake_run(command, stdout, stderr, text, check, timeout):
        assert command == ["nmap", "-Pn", "-oX", "-", "127.0.0.1"]
        assert timeout == 300
        return subprocess.CompletedProcess(command, 0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = nmap_scan.run_nmap_scan("127.0.0.1", "-Pn")

    assert result["status"]["state"] == "up"
    assert result["scan_info"]["protocol"] == "tcp"
    assert result["host"] == "127.0.0.1"
    assert result["ports"] == [{
        "portid": "80",
        "protocol": "tcp",
        "state": "open",
        "service": "http",
    }]


def test_run_nmap_scan_uses_configured_timeout(monkeypatch):
    _force_nmap(monkeypatch)

    def fake_run(command, stdout, stderr, text, check, timeout):
        assert timeout == 7
        return subprocess.CompletedProcess(command, 0, stdout=NMAP_XML, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = nmap_scan.run_nmap_scan("127.0.0.1", "-Pn", {"nmap_timeout": 7})

    assert result["status"]["state"] == "up"


def test_run_nmap_scan_handles_timeout(monkeypatch):
    _force_nmap(monkeypatch)

    def fake_run(command, stdout, stderr, text, check, timeout):
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = nmap_scan.run_nmap_scan("example.com", "-sS", {"nmap_timeout": 9})

    assert result["ports"] == []
    assert result["error"] == "Nmap scan timed out after 9 seconds"


def test_run_nmap_scan_handles_empty_output(monkeypatch):
    _force_nmap(monkeypatch)

    def fake_run(command, stdout, stderr, text, check, timeout):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="permission denied")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = nmap_scan.run_nmap_scan("example.com", "-sS")

    assert result["ports"] == []
    assert result["error"] == "permission denied"


def test_run_nmap_scan_handles_none_output(monkeypatch):
    _force_nmap(monkeypatch)

    def fake_run(command, stdout, stderr, text, check, timeout):
        return subprocess.CompletedProcess(command, 1, stdout=None, stderr=None)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = nmap_scan.run_nmap_scan("example.com", "-sS")

    assert result["ports"] == []
    assert result["error"] == "Nmap did not return XML output"


def test_run_nmap_scan_handles_invalid_xml(monkeypatch):
    _force_nmap(monkeypatch)

    def fake_run(command, stdout, stderr, text, check, timeout):
        return subprocess.CompletedProcess(command, 0, stdout="<nmaprun>", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = nmap_scan.run_nmap_scan("example.com", "-sS")

    assert result["ports"] == []
    assert "Failed to parse Nmap XML output" in result["error"]


def test_run_nmap_scan_handles_missing_nodes(monkeypatch):
    _force_nmap(monkeypatch)

    def fake_run(command, stdout, stderr, text, check, timeout):
        return subprocess.CompletedProcess(command, 0, stdout="<nmaprun><host /></nmaprun>", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = nmap_scan.run_nmap_scan("example.com", "-sS")

    assert result["status"] == {"state": "unknown"}
    assert result["scan_info"] == {}
    assert result["host"] == "Unknown"
    assert result["ports"] == []
