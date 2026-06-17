# ActiveRecon

<div align="center">

![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=for-the-badge\&logo=python)
![Nmap](https://img.shields.io/badge/Nmap-Reconnaissance-lightgrey?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Authorized%20Testing-red?style=for-the-badge)
![Reports](https://img.shields.io/badge/Reports-Markdown%20%2B%20JSON-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-informational?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A Python-based reconnaissance CLI tool for authorized security assessments, lab environments, and security learning.**

ActiveRecon combines **Nmap scanning, DNS analysis, HTTP service detection, TLS checks, header collection, JSON output, Markdown reporting, and interesting signal generation** into a structured recon workflow.

</div>

---

## Demo

> Terminal demo GIF coming soon.

```text
docs/demo.gif
```

When added, place it here:

```markdown
![ActiveRecon Demo](docs/demo.gif)
```

---

## Responsible Use

> **Important:** Only scan systems that you own or have explicit written permission to assess.

ActiveRecon is an active reconnaissance tool. It may generate network traffic that can be detected by monitoring systems.

Do not use ActiveRecon against systems, networks, bug bounty targets, or production environments without clear authorization and defined scope.

---

## Overview

ActiveRecon helps organize early-stage reconnaissance into a repeatable command-line workflow.

Instead of manually running separate commands and collecting notes from different tools, ActiveRecon can:

* run predefined Nmap scan profiles
* check local setup with a no-scan doctor command
* identify open services
* detect HTTP services from scan results
* collect HTTP status, headers, redirects, page titles, and technology hints
* collect TLS certificate metadata for HTTPS services
* query common DNS records
* generate Markdown and JSON reports
* highlight interesting signals for follow-up review

This project is intended for learning, lab use, portfolio development, and authorized testing.

---

## Features

### Reconnaissance Workflow

ActiveRecon currently supports:

| Area      | Capability                                                 |
| --------- | ---------------------------------------------------------- |
| Nmap      | Predefined scan profiles, XML parsing, timeout handling    |
| HTTP      | Status codes, titles, redirects, headers, technology hints |
| TLS       | TLS version, cipher, certificate metadata                  |
| DNS       | A, MX, and TXT lookups                                     |
| Reporting | Markdown and JSON output                                   |
| Safety    | Scope guard, dry-run mode, doctor checks                   |
| Analysis  | Interesting signals for follow-up review                   |

---

## Scan Profiles

Scan profiles are configured in:

```text
activerecon/modules/config/config.yaml
```

Current profiles:

| Profile    | Purpose                                                          |
| ---------- | ---------------------------------------------------------------- |
| `fast`     | Quick scan using top ports                                       |
| `web`      | Web-focused scan for common HTTP/HTTPS and development ports     |
| `standard` | More detailed TCP scan with service and default script detection |
| `full`     | Full TCP port scan with service and default script detection     |
| `udp`      | UDP scan using top UDP ports and script timeout                  |

---

## Example Usage

Run a quick scan:

```bash
activerecon --target example.com --scan-profile fast
```

Run a web-focused scan:

```bash
activerecon --target 127.0.0.1 --scan-profile web --output juice-shop
```

Run a full TCP scan:

```bash
activerecon --target 127.0.0.1 --scan-profile full --output localhost-full
```

Check local setup without scanning:

```bash
activerecon --doctor
```

Use a scope file:

```bash
activerecon --target app.example.com --scope scope.txt --scan-profile standard
```

---

## Example Report Output

ActiveRecon generates timestamped reports under `reports/` by default:

```text
reports/example.com_20260617_090807.md
reports/example.com_20260617_090807.json
```

Generated Markdown reports include sections such as:

```markdown
# Active Recon Report

## Summary
## Scan Information
## Port Scan Results
## HTTP Analysis
## TLS Analysis
## DNS Analysis
## Interesting Signals
```

Example interesting signals:

```text
INFO   [http]       HTTP service detected on port 3000
LOW    [http]       Missing Content-Security-Policy header
INFO   [cors]       Wildcard CORS header observed
INFO   [endpoint]   Interesting path found in response header
INFO   [technology] X-Powered-By header exposed
```

---

## Installation

### Prerequisites

ActiveRecon requires:

* Python 3.6 or later
* Nmap

Install Nmap on Debian/Ubuntu-based systems:

```bash
sudo apt-get update
sudo apt-get install nmap
```

On Windows, install Nmap from the official installer and make sure `nmap.exe` is available in PATH.

ActiveRecon also attempts to resolve Nmap from common Windows install paths.

---

### Install from GitHub

```bash
git clone https://github.com/CamiloCod3/ActiveRecon.git
cd ActiveRecon
pip install .
```

For local development:

```bash
pip install -e .
```

---

## Usage

```bash
activerecon --target <IP_OR_DOMAIN> --scan-profile <PROFILE> [--output <OUTPUT_FILE>] [--output-format md|json|both] [--verbose|--quiet]
activerecon --doctor
```

### Arguments

| Argument          | Description                                                                            |
| ----------------- | -------------------------------------------------------------------------------------- |
| `--target`        | Target IP address or domain name                                                       |
| `--doctor`        | Check Python, Nmap, config loading, and report directory write access without scanning |
| `--scan-profile`  | Nmap scan profile to use                                                               |
| `--output`        | Optional report name or path                                                           |
| `--output-format` | `md`, `json`, or `both`. Defaults to `both`                                            |
| `--scope`         | Optional file with allowed domains, IPs, or CIDR ranges                                |
| `--dry-run`       | Validate arguments and planned outputs without scanning                                |
| `--verbose`       | Show debug logging                                                                     |
| `--quiet`         | Show only warnings and errors                                                          |

---

## Config

Common config values live in:

```text
activerecon/modules/config/config.yaml
```

Example:

```yaml
http_timeout: 5
nmap_timeout: 300

# Optional override if Nmap is installed outside PATH.
# nmap_executable: "C:\\Program Files\\Nmap\\nmap.exe"

scan_profiles:
  fast: "-Pn -n -sT --top-ports 100 -T4"
  web: "-Pn -n -sT -p 80,443,3000,5000,8000,8080,8443,9000,9443 -sV -T3"
  standard: "-Pn -n -sT -sV -sC -T3"
  full: "-Pn -n -sT -p- -sV -sC -T4"
  udp: "-Pn -n -sU --top-ports 100 -sC --script-timeout 5m"
```

---

## Scope Guard

Use `--scope` to require the target to match an allowed domain, IP address, or CIDR range before any scan runs.

Example `scope.txt`:

```text
example.com
192.0.2.0/24
```

Subdomains are allowed when the parent domain is listed.

For example:

```text
example.com
```

allows:

```text
app.example.com
```

---

## JSON Schema

The JSON report uses a simple stable wrapper:

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-06-17T09:08:07Z",
  "target": "example.com",
  "results": {}
}
```

The `results` object contains the same major sections used by the Markdown report, including:

```text
Nmap Scan
HTTP Analysis
TLS Analysis
DNS Analysis
Attention
```

Markdown reports use the heading `Interesting Signals`. JSON output keeps the `Attention` key for compatibility.

---

## Project Structure

```text
ActiveRecon/
|-- activerecon/
|   |-- main.py
|   `-- modules/
|       |-- config/
|       |   `-- config.yaml
|       |-- config_loader.py
|       |-- dns_analysis.py
|       |-- doctor.py
|       |-- http_enum.py
|       |-- json_report.py
|       |-- nmap_scan.py
|       |-- report_generator.py
|       |-- risk_analysis.py
|       |-- scope_guard.py
|       `-- tls_analysis.py
|-- reports/
|-- tests/
|-- .github/workflows/
|-- MANIFEST.in
|-- setup.py
`-- README.md
```

---

## Skills Demonstrated

This project demonstrates practical skills in:

* Python CLI development
* Linux-based security tooling
* Nmap automation
* XML parsing
* DNS analysis
* HTTP service enumeration
* TLS metadata collection
* JSON and Markdown report generation
* modular Python project structure
* security-focused scripting
* authorized reconnaissance methodology

---

## Roadmap

Planned improvements include:

* richer web scanning for the `web` profile
* endpoint discovery from HTML, headers, and JavaScript
* multi-target scanning
* screenshot support for HTTP services
* modern Python packaging with `pyproject.toml`

---

## Disclaimer

This project is for educational purposes, lab environments, and authorized security assessments only.

The author is not responsible for misuse of this tool.

---

## License

This project is licensed under the MIT License.
