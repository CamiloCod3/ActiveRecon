# ActiveRecon

**ActiveRecon** is a Python-based reconnaissance CLI tool designed for authorized security assessments, lab environments, and security learning.

It automates parts of the early reconnaissance process by combining **Nmap scanning, DNS analysis, HTTP service detection, header collection, and Markdown reporting** into a structured workflow.

The goal of this project is to support practical learning around Linux, networking, service enumeration, security assessment methodology, and bug bounty-style reconnaissance workflows.

> **Important:** Only scan systems that you own or have explicit written permission to assess.

---

## Overview

ActiveRecon helps organize common reconnaissance tasks into a repeatable command-line workflow.

Instead of manually running separate commands and collecting notes from different tools, ActiveRecon provides a simple way to:

* run predefined Nmap scan profiles
* identify open services
* detect HTTP services from scan results
* collect basic HTTP status and header information
* query common DNS records
* generate a Markdown report for documentation

This project is built as a practical security automation project and is intended for learning, lab use, and authorized testing.

---

## Features

### Nmap Scanning

Run predefined Nmap scan profiles from a YAML configuration file.

Current scan profiles include:

* `fast`
* `standard`
* `full`
* `udp`

The profiles are configured in:

```text
activerecon/modules/config/config.yaml
```

### DNS Analysis

Query common DNS records for the target domain:

* A records
* MX records
* TXT records

### HTTP Analysis

ActiveRecon identifies HTTP services from Nmap results and performs basic HTTP analysis, including:

* URL construction based on detected port and service
* HTTP/HTTPS scheme detection
* status code collection
* response header collection
* timeout handling

### Markdown Reporting

Generate a structured Markdown report containing:

* target information
* host status
* scan information
* open ports
* detected services
* HTTP results
* DNS results
* error details where applicable

---

## Example Workflow

```bash
activerecon --target example.com --scan-profile fast --output report.md
```

This command will:

1. Run the selected Nmap scan profile against the target.
2. Parse the Nmap XML output.
3. Identify HTTP services from open ports.
4. Collect HTTP status and header details.
5. Query DNS records.
6. Generate a Markdown report.

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

After installation, the `activerecon` command should be available from your terminal.

---

## Usage

```bash
activerecon --target <IP_OR_DOMAIN> --scan-profile <PROFILE> --output <OUTPUT_FILE>
```

### Example

```bash
activerecon --target example.com --scan-profile fast --output report.md
```

### Arguments

| Argument         | Description                      |
| ---------------- | -------------------------------- |
| `--target`       | Target IP address or domain name |
| `--scan-profile` | Nmap scan profile to use         |
| `--output`       | Markdown report output file      |

### Available Scan Profiles

| Profile    | Purpose                                                          |
| ---------- | ---------------------------------------------------------------- |
| `fast`     | Quick scan using top ports                                       |
| `standard` | More detailed TCP scan with service and default script detection |
| `full`     | Full TCP port scan with service and default script detection     |
| `udp`      | UDP scan using top UDP ports and script timeout                  |

---

## Project Structure

```text
ActiveRecon/
├── activerecon/
│   ├── main.py
│   └── modules/
│       ├── config/
│       │   └── config.yaml
│       ├── config_loader.py
│       ├── dns_analysis.py
│       ├── http_enum.py
│       ├── nmap_scan.py
│       └── report_generator.py
├── tests/
│   └── test_main.py
├── MANIFEST.in
├── setup.py
└── README.md
```

---

## Example Report Sections

Generated reports include sections such as:

```markdown
# Active Recon Report

## Scan Information

## Open Ports

## HTTP Analysis

## DNS Analysis
```

The report is intended to support documentation, review, and follow-up analysis after a scan.

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

* security header analysis
* JSON output support
* multi-target scanning
* target validation
* improved error handling
* screenshot support for HTTP services
* technology fingerprinting
* bug bounty-oriented findings section
* GitHub Actions for testing and code quality
* additional unit tests for individual modules
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
* Markdown report generation
* modular Python project structure
* security-focused scripting
* authorized reconnaissance methodology

---

## Portfolio Context

ActiveRecon is part of my hands-on cybersecurity and Linux learning journey.

The project is designed to connect theory with practical skills in:

* Linux administration
* networking fundamentals
* service enumeration
* security assessment workflows
* automation
* documentation
* bug bounty-style reconnaissance

---

## Disclaimer

This project is for educational purposes, lab environments, and authorized security assessments only.

The author is not responsible for misuse of this tool.

---

## License

This project is licensed under the MIT License.
