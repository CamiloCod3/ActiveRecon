import logging

from .models import ReconOptions, ReconResult
from .modules.config_loader import load_config
from .modules.dns_analysis import analyze_dns
from .modules.endpoint_discovery import discover_endpoints
from .modules.http_enum import analyze_http
from .modules.json_report import generate_json_report
from .modules.nmap_scan import run_nmap_scan
from .modules.report_generator import generate_report
from .modules.risk_analysis import generate_attention_findings
from .modules.tls_analysis import analyze_tls
from .output_paths import build_output_paths
from .policies.scope_policy import ScopePolicy
from .targets.parser import parse_target
from .workflows import get_http_ports, web_recon_enabled


CONFIG = None
DNS_IP_SKIP_REASON = "DNS analysis skipped for IP address target"


class ReconValidationError(ValueError):
    pass


def get_config():
    return CONFIG if CONFIG is not None else load_config()


def _dns_skip_result():
    return {
        "skipped": True,
        "reason": DNS_IP_SKIP_REASON,
        "A": [],
        "MX": [],
        "TXT": [],
    }


def _load_config():
    try:
        return get_config()
    except Exception as e:
        raise ReconValidationError(f"Could not load config: {e}") from e


def _scan_command(config, scan_profile):
    scan_profiles = config.get("scan_profiles", {})
    if scan_profile not in scan_profiles:
        choices = ", ".join(sorted(scan_profiles)) or "none configured"
        raise ReconValidationError(
            f"Unknown scan profile '{scan_profile}'. Available profiles: {choices}"
        )
    return scan_profiles[scan_profile]


def _validate_scope(target, scope_file):
    if not scope_file:
        return
    try:
        in_scope = ScopePolicy.from_file(scope_file).allows(target)
    except OSError as e:
        raise ReconValidationError(f"Could not read scope file {scope_file}: {e}") from e
    if not in_scope:
        raise ReconValidationError(f"Target is outside the allowed scope file: {scope_file}")


def run_recon(options: ReconOptions) -> ReconResult:
    config = _load_config()
    scan_command = _scan_command(config, options.scan_profile)
    target_spec = parse_target(options.target)
    markdown_output, json_output = build_output_paths(
        options.target,
        options.output,
        options.output_format,
    )
    recon_result = ReconResult(
        target=options.target,
        target_spec=target_spec,
        scan_profile=options.scan_profile,
        markdown_output=markdown_output,
        json_output=json_output,
        dry_run=options.dry_run,
    )

    _validate_scope(options.target, options.scope)

    logging.info(f"Starting automated recon on target: {options.target}")
    logging.info(f"Using scan profile: {options.scan_profile} ({scan_command})")
    if markdown_output:
        logging.info(f"Markdown report path: {markdown_output}")
    if json_output:
        logging.info(f"JSON report path: {json_output}")

    if options.dry_run:
        logging.info("Dry run requested. No Nmap, HTTP, TLS, or DNS checks were executed.")
        return recon_result

    results = recon_result.results

    try:
        nmap_results = run_nmap_scan(options.target, scan_command, config)
        if not isinstance(nmap_results, dict):
            nmap_results = {
                "target": options.target,
                "ports": [],
                "error": "Nmap scan returned invalid results",
            }
        results["Nmap Scan"] = nmap_results
        if nmap_results.get("error"):
            logging.error(f"Nmap scan completed with errors: {nmap_results['error']}")
        else:
            logging.info(f"Nmap scan completed successfully. Found {len(nmap_results.get('ports', []))} ports.")
    except Exception as e:
        logging.error(f"Error during Nmap scan: {e}")
        nmap_results = {"target": options.target, "ports": [], "error": f"Nmap scan failed: {e}"}
        results["Nmap Scan"] = nmap_results

    http_ports = get_http_ports(nmap_results)
    if http_ports:
        try:
            logging.info(f"HTTP services found: {http_ports}. Running HTTP analysis.")
            results["HTTP Analysis"] = analyze_http(options.target, config, http_ports)
        except Exception as e:
            logging.error(f"Error during HTTP analysis: {e}")
            results["HTTP Analysis"] = {"error": f"HTTP analysis failed: {e}"}
    else:
        logging.info("No HTTP ports found. Skipping HTTP analysis.")
        results["HTTP Analysis"] = []

    try:
        logging.info("Running TLS analysis.")
        results["TLS Analysis"] = analyze_tls(results["HTTP Analysis"], config.get("http_timeout", 5))
    except Exception as e:
        logging.error(f"Error during TLS analysis: {e}")
        results["TLS Analysis"] = {"error": f"TLS analysis failed: {e}"}

    if web_recon_enabled(config, options.scan_profile):
        try:
            logging.info("Running endpoint discovery.")
            results["Endpoint Discovery"] = discover_endpoints(results["HTTP Analysis"], config)
        except Exception as e:
            logging.error(f"Error during endpoint discovery: {e}")
            results["Endpoint Discovery"] = {"error": f"Endpoint discovery failed: {e}"}

    if target_spec.is_ip:
        logging.info(DNS_IP_SKIP_REASON)
        results["DNS Analysis"] = _dns_skip_result()
    else:
        try:
            logging.info("Running DNS analysis.")
            results["DNS Analysis"] = analyze_dns(options.target)
        except Exception as e:
            logging.error(f"Error during DNS analysis: {e}")
            results["DNS Analysis"] = {"error": f"DNS analysis failed: {e}"}

    interesting_signals = generate_attention_findings(results)
    results["Attention"] = interesting_signals
    results["Interesting Signals"] = interesting_signals

    if markdown_output:
        try:
            generate_report(options.target, results, markdown_output)
            logging.info(f"Markdown report saved to {markdown_output}")
        except Exception as e:
            logging.error(f"Error during Markdown report generation: {e}")

    if json_output:
        try:
            generate_json_report(options.target, results, json_output, scan_profile=options.scan_profile)
            logging.info(f"JSON report saved to {json_output}")
        except Exception as e:
            logging.error(f"Error during JSON report generation: {e}")

    logging.info("Recon completed.")
    return recon_result
