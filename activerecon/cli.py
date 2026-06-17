import argparse
import json
import logging

from .models import ReconOptions
from .modules.doctor import run_doctor
from .modules.json_report import build_json_summary
from .output_paths import DEFAULT_REPORT_DIR
from .runner import ReconValidationError, run_recon
from .targets.target_diff import diff_inventories
from .targets.target_inventory import (
    build_inventory,
    export_scope_file,
    load_inventory,
    save_inventory,
)
from .targets.target_loader import load_targets


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
QUIET_LOG_FORMAT = "%(levelname)s: %(message)s"


def configure_logging(verbose=False, quiet=False):
    if verbose:
        level = logging.DEBUG
        log_format = LOG_FORMAT
    elif quiet:
        level = logging.ERROR
        log_format = QUIET_LOG_FORMAT
    else:
        level = logging.WARNING
        log_format = QUIET_LOG_FORMAT

    root_logger = logging.getLogger()
    if root_logger.handlers:
        root_logger.setLevel(level)
        for handler in root_logger.handlers:
            handler.setLevel(level)
            handler.setFormatter(logging.Formatter(log_format))
    else:
        logging.basicConfig(level=level, format=log_format)


def build_parser():
    parser = argparse.ArgumentParser(description="Active Recon Tool")
    parser.add_argument("--target", help="Target IP or domain")
    parser.add_argument("--doctor", action="store_true", help="Check local dependencies and exit without scanning")
    parser.add_argument("--verbose", action="store_true", help="Show detailed internal logs")
    parser.add_argument("--quiet", action="store_true", help="Show only errors and report paths")
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
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate options and show planned outputs without scanning",
    )
    parser.add_argument(
        "--scan-profile",
        default="fast",
        help="Choose a pre-defined Nmap profile from config.yaml",
    )

    subparsers = parser.add_subparsers(dest="command")
    targets_parser = subparsers.add_parser("targets", help="Import, diff, and export target inventories")
    targets_subparsers = targets_parser.add_subparsers(dest="targets_action")

    import_parser = targets_subparsers.add_parser("import", help="Import targets into an inventory file")
    import_parser.add_argument("--input", required=True, help="Input targets file (.txt, .json, or .jsonl)")
    import_parser.add_argument("--output", required=True, help="Output inventory JSON file")

    diff_parser = targets_subparsers.add_parser("diff", help="Compare two inventory files")
    diff_parser.add_argument("--previous", required=True, help="Previous inventory JSON file")
    diff_parser.add_argument("--current", required=True, help="Current inventory JSON file")

    export_parser = targets_subparsers.add_parser("export-scope", help="Export inventory hosts to a scope file")
    export_parser.add_argument("--inventory", required=True, help="Input inventory JSON file")
    export_parser.add_argument("--output", required=True, help="Output scope text file")
    return parser


def options_from_args(args):
    return ReconOptions(
        target=args.target,
        scan_profile=args.scan_profile,
        output=args.output,
        output_format=args.output_format,
        scope=args.scope,
        dry_run=args.dry_run,
        verbose=args.verbose,
        quiet=args.quiet,
    )


def _as_list(value):
    return value if isinstance(value, list) else []


def _dns_summary(result, summary):
    dns_results = result.results.get("DNS Analysis", {})
    if isinstance(dns_results, dict) and dns_results.get("skipped"):
        return "skipped for IP target"
    return f"{summary['dns_records']} records"


def _endpoint_count(result, summary):
    if "Endpoint Discovery" not in result.results:
        return None
    return summary["endpoint_count"]


def _report_paths(result):
    paths = []
    if result.markdown_output:
        paths.append(("Markdown", result.markdown_output))
    if result.json_output:
        paths.append(("JSON", result.json_output))
    return paths


def _inventory_host_count(inventory):
    return len({
        item.get("host")
        for item in inventory.get("targets", [])
        if item.get("host")
    })


def print_report_paths(result, output=print):
    paths = _report_paths(result)
    if not paths:
        return
    for label, path in paths:
        output(f"{label}: {path}")


def print_scan_summary(result, output=print):
    summary = build_json_summary(result.results)
    endpoint_count = _endpoint_count(result, summary)

    title = "ActiveRecon dry run completed" if result.dry_run else "ActiveRecon scan completed"
    output(title)
    output("")
    output(f"Target: {result.target}")
    output(f"Profile: {result.scan_profile}")
    output("")

    if result.dry_run:
        output("No scan executed.")
    else:
        output(f"Nmap: {summary['total_ports_listed']} ports listed, {summary['open_ports']} open")
        output(f"HTTP: {summary['http_services']} service analyzed")
        output(f"TLS: {summary['tls_results']} HTTPS services analyzed")
        output(f"DNS: {_dns_summary(result, summary)}")
        if endpoint_count is not None:
            output(f"Endpoints: {endpoint_count} discovered")
        output(f"Interesting Signals: {summary['interesting_signals']}")

    paths = _report_paths(result)
    if paths:
        output("")
        output("Reports:")
        for label, path in paths:
            output(f"- {label}: {path}")


def run_targets_command(args, output=print):
    if args.targets_action == "import":
        raw_targets = load_targets(args.input)
        inventory = build_inventory(raw_targets, source=args.input)
        save_inventory(inventory, args.output)
        output("ActiveRecon target import completed")
        output(f"Input: {args.input}")
        output(f"Output: {args.output}")
        output(f"Targets loaded: {len(raw_targets)}")
        output(f"Unique targets: {len(inventory['targets'])}")
        output(f"Duplicates removed: {len(raw_targets) - len(inventory['targets'])}")
        output("Scans run: 0")
        return 0

    if args.targets_action == "diff":
        previous = load_inventory(args.previous)
        current = load_inventory(args.current)
        diff = diff_inventories(previous, current)
        output("ActiveRecon target diff completed")
        output(f"Added: {len(diff['added'])}")
        output(f"Removed: {len(diff['removed'])}")
        output(f"Unchanged: {len(diff['unchanged'])}")
        output("Scans run: 0")
        return 0

    if args.targets_action == "export-scope":
        inventory = load_inventory(args.inventory)
        export_scope_file(inventory, args.output)
        output("ActiveRecon scope export completed")
        output(f"Inventory: {args.inventory}")
        output(f"Output: {args.output}")
        output(f"Targets exported: {_inventory_host_count(inventory)}")
        output("Scans run: 0")
        return 0

    raise ValueError("targets requires a subcommand: import, diff, or export-scope")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.verbose and args.quiet:
        parser.error("--verbose and --quiet cannot be used together")

    configure_logging(args.verbose, args.quiet)

    if args.doctor:
        run_doctor(DEFAULT_REPORT_DIR)
        return 0

    if args.command == "targets":
        try:
            return run_targets_command(args)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            parser.error(str(e))
            return 2

    if not args.target:
        parser.error("--target is required unless --doctor is used")

    try:
        result = run_recon(options_from_args(args))
    except ReconValidationError as e:
        parser.error(str(e))
        return 2

    if args.quiet:
        print_report_paths(result)
    else:
        print_scan_summary(result)
    return 0
