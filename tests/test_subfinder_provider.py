from types import SimpleNamespace

import pytest

from activerecon.discovery import subfinder_provider


def test_resolve_subfinder_executable_uses_config_override(tmp_path):
    executable = tmp_path / "subfinder.exe"
    executable.write_text("", encoding="utf-8")

    assert subfinder_provider.resolve_subfinder_executable({
        "subfinder_executable": str(executable),
    }) == str(executable)


def test_resolve_subfinder_executable_uses_path(monkeypatch):
    monkeypatch.setattr(
        subfinder_provider.shutil,
        "which",
        lambda name: "C:\\Tools\\subfinder.exe" if name == "subfinder" else None,
    )

    assert subfinder_provider.resolve_subfinder_executable() == "C:\\Tools\\subfinder.exe"


def test_resolve_subfinder_executable_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(subfinder_provider.shutil, "which", lambda name: None)
    monkeypatch.setattr(subfinder_provider.Path, "home", lambda: tmp_path)

    assert subfinder_provider.resolve_subfinder_executable() is None

    with pytest.raises(FileNotFoundError, match="subfinder executable was not found"):
        subfinder_provider.run_subfinder("example.com")


def test_run_subfinder_parses_stdout_and_uses_expected_command(monkeypatch):
    captured = {}

    def fake_run(command, stdout, stderr, text, check, timeout):
        captured["command"] = command
        captured["timeout"] = timeout
        return SimpleNamespace(
            stdout="api.example.com\n\nwww.example.com\napi.example.com\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(subfinder_provider, "resolve_subfinder_executable", lambda config=None: "subfinder")
    monkeypatch.setattr(subfinder_provider.subprocess, "run", fake_run)

    results = subfinder_provider.run_subfinder("example.com", config={"subfinder_timeout": "9"})

    assert results == ["api.example.com", "www.example.com", "api.example.com"]
    assert captured["command"] == ["subfinder", "-d", "example.com", "-silent"]
    assert captured["timeout"] == 9
