import argparse
import logging

from .modules.nmap_scan import run_nmap_scan
from .modules.http_enum import analyze_http
from .modules.dns_analysis import analyze_dns
from .modules.report_generator import generate_report
from .modules.config_loader import load_config


CONFIG = load_config()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


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


def main():
    parser = argparse.ArgumentParser(description="Active Recon Tool")
    parser.add_argument("--target", required=True, help="Target IP or domain")
    parser.add_argument("--output", default="report.md", help="Output file for the report")

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
    results = {}

    logging.info(f"Starting automated recon on target: {target}")
    logging.info(f"Using scan profile: {chosen_profile} ({scan_command})")

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
        logging.info("Running DNS analysis.")
        results["DNS Analysis"] = analyze_dns(target)
    except Exception as e:
        logging.error(f"Error during DNS analysis: {e}")
        results["DNS Analysis"] = {"error": f"DNS analysis failed: {e}"}

    try:
        generate_report(target, results, args.output)
        logging.info(f"Recon completed successfully! Report saved to {args.output}")
    except Exception as e:
        logging.error(f"Error during report generation: {e}")


if __name__ == "__main__":
    main()
