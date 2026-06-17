import argparse
import logging

from .models import ReconOptions
from .modules.doctor import run_doctor
from .output_paths import DEFAULT_REPORT_DIR
from .runner import ReconValidationError, run_recon


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"


def configure_logging(verbose=False, quiet=False):
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    root_logger = logging.getLogger()
    if root_logger.handlers:
        root_logger.setLevel(level)
        for handler in root_logger.handlers:
            handler.setLevel(level)
    else:
        logging.basicConfig(level=level, format=LOG_FORMAT)


def build_parser():
    parser = argparse.ArgumentParser(description="Active Recon Tool")
    parser.add_argument("--target", help="Target IP or domain")
    parser.add_argument("--doctor", action="store_true", help="Check local dependencies and exit without scanning")
    parser.add_argument("--verbose", action="store_true", help="Show debug logging")
    parser.add_argument("--quiet", action="store_true", help="Only show warnings and errors")
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
        return None

    if not args.target:
        parser.error("--target is required unless --doctor is used")

    try:
        return run_recon(options_from_args(args))
    except ReconValidationError as e:
        parser.error(str(e))
    return None
