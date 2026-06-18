# ActiveRecon

<div align="center">

![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=for-the-badge\&logo=python)
![Nmap](https://img.shields.io/badge/Nmap-Reconnaissance-lightgrey?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Authorized%20Testing-red?style=for-the-badge)
![Reports](https://img.shields.io/badge/Reports-Markdown%20%2B%20JSON-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-informational?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A Python-based reconnaissance CLI tool for authorized security assessments, lab environments, and security learning.**

ActiveRecon combines **Nmap scanning, HTTP and TLS analysis, DNS checks, web endpoint discovery, Markdown reports, JSON schema output, and interesting signal generation** into a structured recon workflow.

</div>

---

## Quick Start

Run a web-focused recon workflow and save timestamped Markdown and JSON reports under `reports/`:

```bash
activerecon --target 127.0.0.1 --scan-profile web --output juice-shop
```

Run a local OWASP Juice Shop lab scan with a URL target:

```bash
python -m activerecon.main --target http://127.0.0.1:3000/ --scope docs/examples/scopes/local_lab_scope.json --scan-profile web --output juice-shop
```

ActiveRecon accepts IP addresses, domain names, and URLs as targets.

Check your local setup without scanning anything:

```bash
activerecon --doctor
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
* check local setup with a no-scan `--doctor` command
* identify open, closed, and filtered port results
* detect HTTP services from open Nmap ports, including common web and development ports
* collect HTTP status, final URLs, redirects, page titles, headers, missing security headers, and technology hints
* collect TLS certificate metadata for HTTPS services
* query A, MX, and TXT DNS records, while skipping noisy DNS lookups for IP address targets
* run endpoint discovery automatically from the `web` scan profile
* import, normalize, deduplicate, diff, and export target inventories without scanning
* run passive subdomain discovery through optional external `subfinder` without scanning
* generate timestamped Markdown and JSON reports under `reports/`
* highlight interesting signals for follow-up review

This project is intended for learning, lab use, portfolio development, and authorized testing.

---

## Features

### Reconnaissance Workflow

ActiveRecon currently supports:

| Area      | Capability                                                                 |
| --------- | -------------------------------------------------------------------------- |
| Nmap      | Scan profiles, executable discovery, XML parsing, timeout and error results |
| HTTP      | Status, title, final URL, redirects, headers, missing headers, tech hints   |
| TLS       | TLS version, cipher, subject, issuer, and certificate validity dates         |
| DNS       | Separate A, MX, and TXT lookups, with clean IP-target skip behavior          |
| Web       | Endpoint discovery from HTML, headers, JavaScript, robots.txt, and probes    |
| Inventory | Target import, normalization, deduplication, diff, and scope export           |
| Discovery | Passive subdomain discovery through optional external `subfinder`             |
| Reporting | Timestamped Markdown and JSON schema `1.1` reports                           |
| Safety    | Responsible-use notice, scope guard, dry-run mode, doctor checks             |
| Analysis  | Low-noise interesting signals for follow-up review                           |

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
| `web`      | Web workflow for HTTP/HTTPS and common development ports         |
| `standard` | More detailed TCP scan with service and default script detection |
| `full`     | Full TCP port scan with service and default script detection     |
| `udp`      | UDP scan using top UDP ports and script timeout                  |

The `web` profile is a workflow preset. It runs the web-focused Nmap profile, HTTP analysis, TLS analysis where applicable, endpoint discovery, interesting signal generation, and Markdown plus JSON reporting.

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

Run a web-focused scan with a URL target:

```bash
python -m activerecon.main --target http://127.0.0.1:3000/ --scope docs/examples/scopes/local_lab_scope.json --scan-profile web --output juice-shop
```

Generate only JSON output:

```bash
activerecon --target example.com --scan-profile web --output example-web --output-format json
```

Preview planned report paths without scanning:

```bash
activerecon --target example.com --scan-profile fast --dry-run
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

Check a URL target against a JSON scope file without scanning:

```bash
python -m activerecon.main scope check --target http://127.0.0.1:3000/ --scope docs/examples/scopes/local_lab_scope.json
```

Import target inventory without scanning:

```bash
python -m activerecon.main targets import --input docs/examples/lab/local_targets.txt --output inventories/local_lab.json
```

Compare two inventories without scanning:

```bash
python -m activerecon.main targets diff --previous inventories/old.json --current inventories/latest.json
```

Export normalized inventory hosts to a scope file:

```bash
python -m activerecon.main targets export-scope --inventory inventories/local_lab.json --output scopes/local_lab.txt
```

Run passive subdomain discovery without scanning:

```bash
python -m activerecon.main discover subdomains --domain example.com --scope docs/examples/scopes/example_program_scope.json --output inventories/example_discovered.json
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
## Endpoint Discovery
## TLS Analysis
## DNS Analysis
## Interesting Signals
```

Markdown reports also include:

* a scan context note for local, private, Docker, virtualization, or lab targets
* open ports shown before other port states
* endpoint discovery grouped into API-like endpoints, frontend routes, well-known/probed paths, and static assets
* static asset summaries instead of long asset lists
* cautious wording such as "follow-up recommended" instead of confirmed vulnerability language

Example interesting signals:

```text
INFO   [http]       HTTP service detected on port 3000
LOW    [http]       Missing Content-Security-Policy header
INFO   [cors]       Wildcard CORS header observed
INFO   [endpoint]   API-like endpoint discovered; follow-up recommended
INFO   [endpoint]   Interesting path found in response header X-Recruiting
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

The `--doctor` command checks Python, Nmap availability, the resolved Nmap path, config loading, and whether the reports directory is writable.

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
activerecon --target <IP_DOMAIN_OR_URL> --scan-profile <PROFILE> [--output <OUTPUT_FILE>] [--output-format md|json|both] [--verbose|--quiet]
activerecon --doctor
activerecon targets import --input <TARGETS_FILE> --output <INVENTORY_JSON>
activerecon targets diff --previous <OLD_JSON> --current <NEW_JSON>
activerecon targets export-scope --inventory <INVENTORY_JSON> --output <SCOPE_FILE>
activerecon scope check --target <TARGET> --scope <SCOPE_FILE>
activerecon discover subdomains --domain <DOMAIN> [--scope <SCOPE_FILE>] --output <INVENTORY_JSON>
```

### Arguments

| Argument          | Description                                                                            |
| ----------------- | -------------------------------------------------------------------------------------- |
| `--target`        | Target IP address, domain name, or URL                                                 |
| `--doctor`        | Check Python, Nmap, config loading, and report directory write access without scanning |
| `--scan-profile`  | Nmap scan profile to use                                                               |
| `--output`        | Optional report name or path                                                           |
| `--output-format` | `md`, `json`, or `both`. Defaults to `both`                                            |
| `--scope`         | Optional file with allowed domains, IPs, or CIDR ranges                                |
| `--dry-run`       | Validate arguments and planned outputs without scanning                                |
| `--verbose`       | Show detailed internal logs                                                            |
| `--quiet`         | Suppress the normal summary and show only errors plus report paths                     |

---

## Target Formats

ActiveRecon accepts:

* IP addresses, such as `127.0.0.1`
* domain names, such as `example.com`
* URLs, such as `http://127.0.0.1:3000/`

For scans, URL targets are normalized to their host before Nmap, HTTP analysis, and DNS analysis run. The original target string is still preserved in terminal output, Markdown reports, JSON reports, and generated report names.

Example:

```text
raw target:    http://127.0.0.1:3000/
scan host:     127.0.0.1
report target: http://127.0.0.1:3000/
```

Scope validation uses the original target string, so JSON URL scope rules still work.

---

## Target Inventory

Inventory commands are intentionally separate from scanning. They do not run Nmap, HTTP checks, DNS lookups, endpoint discovery, or reports.

Supported import formats:

| Format  | Behavior                                                     |
| ------- | ------------------------------------------------------------ |
| `.txt`  | One target per line. Blank lines and `#` comments are ignored |
| `.json` | List of strings, list of objects, or inventory-like object    |
| `.jsonl` | One string or object per line                                |

For JSON objects, ActiveRecon reads the first useful field from:

```text
target, url, host, domain, uri
```

Inventory files use schema version `1.0`:

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-06-17T18:05:44Z",
  "source": "targets.txt",
  "targets": []
}
```

Scope export writes one normalized host per line, compatible with the current `--scope` file behavior.

---

## Passive Subdomain Discovery

ActiveRecon can optionally run passive subdomain discovery through the external `subfinder` CLI:

```bash
python -m activerecon.main discover subdomains --domain example.com --scope docs/examples/scopes/example_program_scope.json --output inventories/example_discovered.json
```

This command:

* runs `subfinder -d <domain> -silent`
* parses stdout lines
* normalizes and deduplicates discovered targets using the inventory logic
* evaluates each result against the scope file when `--scope` is provided
* writes inventory-style JSON with provider and scope metadata
* prints `Scans run: 0`

This command does not run Nmap, HTTP probing, TLS checks, DNS analysis, endpoint discovery, Markdown/JSON scan reports, screenshots, nuclei, httpx, APIs, AI analysis, or batch scanning.

`subfinder` is optional and must be installed separately. ActiveRecon does not install, vendor, or configure `subfinder` provider API keys. Subfinder manages its own provider configuration.

ActiveRecon resolves `subfinder` from:

```text
subfinder_executable or subfinder_path in config
PATH: subfinder or subfinder.exe
~/go/bin/subfinder or ~/go/bin/subfinder.exe
```

Generated discovery inventories should be treated as local output and should normally not be committed.

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

# Optional external passive discovery tool path.
# subfinder_executable: "C:\\Tools\\subfinder.exe"
# subfinder_timeout: 120

scan_profiles:
  fast: "-Pn -n -sT --top-ports 100 -T4"
  web: "-Pn -n -sT -p 80,443,3000,5000,8000,8080,8443,9000,9443 -sV -T3"
  standard: "-Pn -n -sT -sV -sC -T3"
  full: "-Pn -n -sT -p- -sV -sC -T4"
  udp: "-Pn -n -sU --top-ports 100 -sC --script-timeout 5m"

web_recon:
  enabled_profiles:
    - web
  endpoint_probe_limit: 50
  fetch_javascript: true
  same_origin_only: true
  well_known_paths:
    - /robots.txt
    - /sitemap.xml
    - /.well-known/security.txt
    - /api
    - /rest
    - /ftp
    - /admin
    - /login
    - /debug
    - /swagger
    - /api-docs
```

---

## Scope Guard

Use `--scope` to require the target to match an allowed domain, IP address, or CIDR range before any scan runs.

Both legacy text scope files and JSON scope files are supported.

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

JSON scope files use schema version `2.0`. They support allowed and denied domains, wildcards, URLs, IP addresses, and CIDR ranges. Denied rules always override allowed rules.

Supported JSON sections:

```text
allowed.domains
allowed.wildcards
allowed.urls
allowed.ips
allowed.cidrs
denied.domains
denied.wildcards
denied.urls
denied.ips
denied.cidrs
```

Check a target against a scope file without scanning:

```bash
activerecon scope check --target api.example.com --scope docs/examples/scopes/example_program_scope.json
```

Check a local lab URL target without scanning:

```bash
python -m activerecon.main scope check --target http://127.0.0.1:3000/ --scope docs/examples/scopes/local_lab_scope.json
```

Scope checks print the matched reason and always report `Scans run: 0`.

---

## JSON Schema

The JSON report uses schema version `1.1` and keeps existing result keys for backwards compatibility.

```json
{
  "schema_version": "1.1",
  "generated_at": "2026-06-17T09:08:07Z",
  "target": "example.com",
  "metadata": {
    "tool": "ActiveRecon",
    "scan_profile": "web",
    "authorized_use_notice": true
  },
  "summary": {
    "host_status": "up",
    "total_ports_listed": 5,
    "open_ports": 3,
    "http_services": 1,
    "tls_results": 0,
    "dns_records": 1,
    "interesting_signals": 4,
    "endpoint_count": 6
  },
  "results": {}
}
```

Top-level metadata may include:

| Field                   | Meaning                                             |
| ----------------------- | --------------------------------------------------- |
| `tool`                  | Tool name, currently `ActiveRecon`                  |
| `scan_profile`          | Selected scan profile when available                |
| `scan_context`          | Local/private/lab context note when applicable      |
| `authorized_use_notice` | Always `true` to mark authorized-use expectations   |

The `results` object contains the same major sections used by the Markdown report, including:

```text
Nmap Scan
HTTP Analysis
Endpoint Discovery
TLS Analysis
DNS Analysis
Attention
Interesting Signals
```

Markdown reports use the heading `Interesting Signals`. JSON output keeps `results["Attention"]` for backwards compatibility. New JSON consumers should prefer `results["Interesting Signals"]`.

When the `web` profile is used, `results["Endpoint Discovery"]` keeps the original flat `endpoints` list and also adds machine-readable summary and category fields.

Endpoint discovery categories currently include:

```text
api_like
frontend_routes
static_assets
well_known
header_discovered
realtime_services
```

The JSON `endpoint_count` counts unique endpoint paths from the flat endpoint list.

---

## Generated Local Files

ActiveRecon creates local output while testing and scanning. These files are generated artifacts and should normally stay out of commits:

```text
reports/
inventories/
scopes/
.pytest_tmp/
.tmp/
```

Keep documentation examples under `docs/examples/`; keep local scan output in generated folders.

---

## Project Structure

```text
ActiveRecon/
|-- activerecon/
|   |-- cli.py
|   |-- cli_output.py
|   |-- main.py
|   |-- models.py
|   |-- output_paths.py
|   |-- runner.py
|   |-- workflows.py
|   |-- commands/
|   |   |-- discover_command.py
|   |   |-- scope_command.py
|   |   `-- targets_command.py
|   |-- discovery/
|   |   `-- subfinder_provider.py
|   |-- modules/
|   |   |-- config/
|   |   |   `-- config.yaml
|   |   |-- config_loader.py
|   |   |-- dns_analysis.py
|   |   |-- doctor.py
|   |   |-- endpoint_categories.py
|   |   |-- endpoint_discovery.py
|   |   |-- http_enum.py
|   |   |-- json_report.py
|   |   |-- nmap_scan.py
|   |   |-- report_generator.py
|   |   |-- risk_analysis.py
|   |   |-- scope_guard.py
|   |   `-- tls_analysis.py
|   |-- policies/
|   |   `-- scope_policy.py
|   |-- targets/
|   |   |-- parser.py
|   |   |-- target_diff.py
|   |   |-- target_inventory.py
|   |   `-- target_loader.py
|-- docs/
|   `-- examples/
|       |-- lab/
|       `-- scopes/
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

Possible future improvements include:

* richer scope policy metadata and validation messages
* inventory history views and cleaner inventory diff summaries
* optional SARIF or CSV export
* richer TLS and certificate review signals
* explicit scope-aware batch scanning with safe limits and dry-run previews
* modern Python packaging with `pyproject.toml`

---

## Disclaimer

This project is for educational purposes, lab environments, and authorized security assessments only.

The author is not responsible for misuse of this tool.

---

## License

This project is licensed under the MIT License.
