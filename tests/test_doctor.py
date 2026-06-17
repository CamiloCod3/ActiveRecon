from activerecon.modules import doctor


def test_run_doctor_prints_clear_status_lines(monkeypatch, tmp_path):
    missing_nmap = tmp_path / "missing-nmap.exe"
    lines = []

    monkeypatch.setattr(doctor, "load_config", lambda: {"nmap_executable": str(missing_nmap)})
    monkeypatch.setattr(doctor, "get_config_path", lambda: tmp_path / "config.yaml")
    monkeypatch.setattr(doctor, "resolve_nmap_executable", lambda config: None)

    doctor.run_doctor(tmp_path / "reports", lines.append)

    assert lines[0] == "ActiveRecon doctor"
    assert any(line.startswith("PASS Python version:") for line in lines)
    assert any(line.startswith("PASS Config loading:") for line in lines)
    assert any(line.startswith("WARN Configured Nmap executable:") for line in lines)
    assert any(line == "FAIL Nmap availability: not found" for line in lines)
    assert any(line.startswith("PASS Reports directory writable:") for line in lines)


def test_run_doctor_continues_when_config_fails(monkeypatch, tmp_path):
    lines = []

    def broken_config():
        raise FileNotFoundError("missing config")

    monkeypatch.setattr(doctor, "load_config", broken_config)
    monkeypatch.setattr(doctor, "resolve_nmap_executable", lambda config: "nmap")

    doctor.run_doctor(tmp_path / "reports", lines.append)

    assert any(line == "FAIL Config loading: missing config" for line in lines)
    assert any(line == "PASS Nmap executable: nmap" for line in lines)
