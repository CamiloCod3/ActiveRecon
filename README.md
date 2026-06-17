# ActiveRecon

**ActiveRecon** is a Python-based reconnaissance CLI tool designed for authorized security assessments, lab environments, and security learning.

It automates parts of early reconnaissance by combining **Nmap scanning, DNS analysis, HTTP service detection, TLS checks, header collection, JSON output, and Markdown reporting** into a structured workflow.

> **Important:** Only scan systems that you own or have explicit written permission to assess.

---

## Overview

ActiveRecon helps organize common reconnaissance tasks into a repeatable command-line workflow.

Instead of manually running separate commands and collecting notes from different tools, ActiveRecon can:

* run predefined Nmap scan profiles
* identify open services
* detect HTTP services from scan results
* collect HTTP status, headers, redirects, page titles, and simple technology hints
* collect TLS certificate metadata for HTTPS services
* query common DNS records
* generate Markdown and JSON reports
* highlight attention findings for follow-up review

This project is intended for learning, lab use, and authorized testing.

---

## Features

### Nmap Scanning

Run predefined Nmap scan profiles from `activerecon/modules/config/config.yaml`.

Current scan profiles:

* `fast`
* `standard`
* `full`
* `udp`

### DNS Analysis

Query common DNS records for the target domain:

* A records
* MX records
* TXT records

### HTTP Analysis

ActiveRecon identifies HTTP services from Nmap results and collects:

* constructed HTTP/HTTPS URLs
* status codes
* final URL and redirect chain
* page title
* response headers
* common security header presence/missing state
* simple technology hints from HTTP headers
* timeout and request errors

### TLS Analysis

For HTTPS services, ActiveRecon collects:

* negotiated TLS version
* cipher name
* certificate subject and issuer
* certificate validity dates
* DNS Subject Alternative Names

### Reports and Findings

Reports include:

* target information
* host status
* scan information
* open ports
* HTTP results
* TLS results
* DNS results
* attention findings
* error details where applicable

By default, ActiveRecon writes both Markdown and JSON reports.

---

## Example Workflow

```bash
activerecon --target example.com --scan-profile fast
```

This command will:

1. Run the selected Nmap scan profile against the target.
2. Parse the Nmap XML output.
3. Identify HTTP services from open ports.
4. Collect HTTP status, header, redirect, title, and fingerprint details.
5. Collect TLS metadata for HTTPS services.
6. Query DNS records.
7. Generate Markdown and JSON reports.

By default, reports are saved under `reports/` with timestamped filenames:

```text
reports/example.com_20260617_090807.md
reports/example.com_20260617_090807.json
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

### Install from GitHub

```bash
git clone https://github.com/CamiloCod3/ActiveRecon.git
cd ActiveRecon
pip install .
```

---

## Usage

```bash
activerecon --target <IP_OR_DOMAIN> --scan-profile <PROFILE> [--output <OUTPUT_FILE>] [--output-format md|json|both]
```

### Examples

```bash
activerecon --target example.com --scan-profile fast
activerecon --target example.com --scan-profile fast --output-format json --output reports/example.json
activerecon --target app.example.com --scope scope.txt --scan-profile standard
activerecon --target example.com --scan-profile fast --dry-run
```

### Arguments

| Argument | Description |
| --- | --- |
| `--target` | Target IP address or domain name |
| `--scan-profile` | Nmap scan profile to use |
| `--output` | Optional report name or path. Bare names are saved as `reports/<name>_<timestamp>.<ext>` |
| `--output-format` | `md`, `json`, or `both`. Defaults to `both` |
| `--scope` | Optional file with allowed domains, IPs, or CIDR ranges |
| `--dry-run` | Validate arguments and planned outputs without scanning |

When `--output` is omitted, the target name is used:

```text
reports/example.com_20260617_090807.md
reports/example.com_20260617_090807.json
```

When `--output report.md` is provided, `report` becomes the report basename and the files still land in `reports/` with a timestamp:

```text
reports/report_20260617_090807.md
reports/report_20260617_090807.json
```

### Available Scan Profiles

| Profile | Purpose |
| --- | --- |
| `fast` | Quick scan using top ports |
| `standard` | More detailed TCP scan with service and default script detection |
| `full` | Full TCP port scan with service and default script detection |
| `udp` | UDP scan using top UDP ports and script timeout |

### Scope Guard

Use `--scope` to require the target to match an allowed domain, IP address, or CIDR range before any scan runs.

Example `scope.txt`:

```text
example.com
192.0.2.0/24
```

Subdomains are allowed when the parent domain is listed. For example, `example.com` allows `app.example.com`.

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

The `results` object contains the same sections used by the Markdown report, including `Nmap Scan`, `HTTP Analysis`, `TLS Analysis`, `DNS Analysis`, and `Attention`.

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

## Report Sections

Generated Markdown reports include sections such as:

```markdown
# Active Recon Report

## Scan Information
## Open Ports
## HTTP Analysis
## TLS Analysis
## DNS Analysis
## Attention Findings
```

---

## Security and Responsible Use

ActiveRecon is an active reconnaissance tool. It may generate network traffic that can be detected by monitoring systems.

Use this tool only when you have permission to test the target.

Do not use ActiveRecon against:

* systems you do not own
* public targets without authorization
* bug bounty programs outside the defined scope
* production systems without approval
* networks where scanning is prohibited

When using this tool in bug bounty or lab environments, always confirm the scope and rules of engagement before scanning.

---

## Roadmap

Planned improvements include:

* multi-target scanning
* screenshot support for HTTP services
* modern Python packaging with `pyproject.toml`

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

## Disclaimer

This project is for educational purposes, lab environments, and authorized security assessments only.

The author is not responsible for misuse of this tool.

---

## License

This project is licensed under the MIT License.
