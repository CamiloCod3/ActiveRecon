import argparse
import json
import logging

from .cli_output import print_report_paths, print_scan_summary
from .commands.scope_command import run_scope_command
from .commands.targets_command import run_targets_command
from .models import ReconOptions
from .modules.doctor import run_doctor
from .output_paths import DEFAULT_REPORT_DIR
from .runner import ReconValidationError, run_recon


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

    scope_parser = subparsers.add_parser("scope", help="Check whether a target is allowed by scope")
    scope_subparsers = scope_parser.add_subparsers(dest="scope_action")
    check_parser = scope_subparsers.add_parser("check", help="Evaluate one target against a scope file")
    check_parser.add_argument("--target", required=True, help="Target IP, domain, or URL to evaluate")
    check_parser.add_argument("--scope", required=True, help="Scope file (.txt or .json)")
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

    if args.command == "scope":
        try:
            return run_scope_command(args)
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
