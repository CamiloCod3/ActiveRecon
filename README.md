# ActiveRecon

ActiveRecon is an automated reconnaissance tool that combines Nmap scanning, DNS analysis, and HTTP analysis.

Only scan systems that you own or have explicit permission to assess.

## Features

- **Nmap Scanning**: Execute predefined profiles for fast, standard, full, or UDP scanning.
- **DNS Analysis**: Query A, MX, and TXT records independently.
- **HTTP Analysis**: Identify HTTP services from Nmap results and fetch basic status/header details.
- **Markdown Reports**: Save Nmap, HTTP, DNS, and error details in one report.

## Installation

### Prerequisites

- **Python 3.6 or later**
- **Nmap**

Install Nmap on Debian/Ubuntu:

```bash
sudo apt-get install nmap
```

### Install from GitHub

```bash
git clone https://github.com/CamiloCod3/ActiveRecon.git
cd ActiveRecon
pip install .
```

## Usage

Run ActiveRecon as a command-line utility:

```bash
activerecon --target <IP_OR_DOMAIN> --scan-profile <PROFILE> --output <OUTPUT_FILE>
```

Example:

```bash
activerecon --target example.com --scan-profile fast --output report.md
```

Available scan profiles are configured in `activerecon/modules/config/config.yaml`.
