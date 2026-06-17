import argparse
import logging
import re
from datetime import datetime
from pathlib import Path

from .modules.nmap_scan import run_nmap_scan
from .modules.http_enum import analyze_http
from .modules.dns_analysis import analyze_dns
from .modules.report_generator import generate_report
from .modules.json_report import generate_json_report
from .modules.config_loader import load_config
from .modules.risk_analysis import generate_attention_findings
from .modules.scope_guard import is_target_in_scope
from .modules.tls_analysis import analyze_tls


CONFIG = load_config()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


DEFAULT_REPORT_DIR = "reports"


def _is_http_service(port):
    service = str(port.get("service", "")).lower()
    state = str(port.get("state", "")).lower()
    portid = str(port.get("portid", ""))

    if state and state != "open":
        return False

    return "http" in service or portid in {"80", "443", "8080", "8443"}


def _get_http_ports(nmap_results):
    ports = nmap_results.get("ports", []) if isinstance(nmap_results, dict) else []
    return [port for port in ports if _is_http_service(port)]


def _safe_report_name(target):
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("._-")
    return safe_name or "target"


def build_report_path(target, output=None, now=None, suffix=".md"):
    timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")

    if output:
        output_path = Path(output)
        output_dir = output_path.parent if output_path.parent != Path(".") else Path(DEFAULT_REPORT_DIR)
        stem = _safe_report_name(output_path.stem)
    else:
        output_dir = Path(DEFAULT_REPORT_DIR)
        stem = _safe_report_name(target)

    filename = f"{stem}_{timestamp}{suffix}"
    return str(output_dir / filename)


def build_output_paths(target, output=None, output_format="both", now=None):
    now = now or datetime.now()
    markdown_path = build_report_path(target, output, now, ".md")
    markdown = markdown_path if output_format in {"md", "both"} else None

    json_path = build_report_path(target, output, now, ".json")
    json_output = json_path if output_format in {"json", "both"} else None
    return markdown, json_output


def main():
    parser = argparse.ArgumentParser(description="Active Recon Tool")
    parser.add_argument("--target", required=True, help="Target IP or domain")
    parser.add_argument(
        "--output",
        default=None,
        help="Report name or path. Bare names are saved as reports/<name>_<timestamp>.<ext>.",
    )
    parser.add_argument(
        "--output-format",
        choices=("md", "json", "both"),
        default="both",
        help="Report output format. Defaults to both Markdown and JSON.",
    )
    parser.add_argument("--scope", help="Optional scope file with allowed domains, IPs, or CIDRs")
    parser.add_argument("--dry-run", action="store_true", help="Validate options and show planned outputs without scanning")

    scan_profile_choices = list(CONFIG["scan_profiles"].keys())
    parser.add_argument(
        "--scan-profile",
        default="fast",
        choices=scan_profile_choices,
        help="Choose a pre-defined Nmap profile from config.yaml",
    )

    args = parser.parse_args()

    chosen_profile = args.scan_profile
    scan_command = CONFIG["scan_profiles"][chosen_profile]

    target = args.target
    markdown_output, json_output = build_output_paths(target, args.output, args.output_format)
    results = {}

    if args.scope:
        try:
            in_scope = is_target_in_scope(target, args.scope)
        except OSError as e:
            parser.error(f"Could not read scope file {args.scope}: {e}")
        if not in_scope:
            parser.error(f"Target is outside the allowed scope file: {args.scope}")

    logging.info(f"Starting automated recon on target: {target}")
    logging.info(f"Using scan profile: {chosen_profile} ({scan_command})")
    if markdown_output:
        logging.info(f"Markdown report path: {markdown_output}")
    if json_output:
        logging.info(f"JSON report path: {json_output}")

    if args.dry_run:
        logging.info("Dry run requested. No Nmap, HTTP, TLS, or DNS checks were executed.")
        return

    try:
        nmap_results = run_nmap_scan(target, scan_command)
        if not isinstance(nmap_results, dict):
            nmap_results = {"target": target, "ports": [], "error": "Nmap scan returned invalid results"}
        results["Nmap Scan"] = nmap_results
        if nmap_results.get("error"):
            logging.error(f"Nmap scan completed with errors: {nmap_results['error']}")
        else:
            logging.info(f"Nmap scan completed successfully. Found {len(nmap_results.get('ports', []))} ports.")
    except Exception as e:
        logging.error(f"Error during Nmap scan: {e}")
        nmap_results = {"target": target, "ports": [], "error": f"Nmap scan failed: {e}"}
        results["Nmap Scan"] = nmap_results

    http_ports = _get_http_ports(nmap_results)
    if http_ports:
        try:
            logging.info(f"HTTP services found: {http_ports}. Running HTTP analysis.")
            results["HTTP Analysis"] = analyze_http(target, CONFIG, http_ports)
        except Exception as e:
            logging.error(f"Error during HTTP analysis: {e}")
            results["HTTP Analysis"] = {"error": f"HTTP analysis failed: {e}"}
    else:
        logging.info("No HTTP ports found. Skipping HTTP analysis.")
        results["HTTP Analysis"] = []

    try:
        logging.info("Running TLS analysis.")
        results["TLS Analysis"] = analyze_tls(results["HTTP Analysis"], CONFIG.get("http_timeout", 5))
    except Exception as e:
        logging.error(f"Error during TLS analysis: {e}")
        results["TLS Analysis"] = {"error": f"TLS analysis failed: {e}"}

    try:
        logging.info("Running DNS analysis.")
        results["DNS Analysis"] = analyze_dns(target)
    except Exception as e:
        logging.error(f"Error during DNS analysis: {e}")
        results["DNS Analysis"] = {"error": f"DNS analysis failed: {e}"}

    results["Attention"] = generate_attention_findings(results)

    if markdown_output:
        try:
            generate_report(target, results, markdown_output)
            logging.info(f"Markdown report saved to {markdown_output}")
        except Exception as e:
            logging.error(f"Error during Markdown report generation: {e}")

    if json_output:
        try:
            generate_json_report(target, results, json_output)
            logging.info(f"JSON report saved to {json_output}")
        except Exception as e:
            logging.error(f"Error during JSON report generation: {e}")

    logging.info("Recon completed.")


if __name__ == "__main__":
    main()
