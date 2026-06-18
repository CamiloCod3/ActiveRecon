from ..discovery.subfinder_provider import run_subfinder
from ..modules.config_loader import load_config
from ..policies.scope_policy import ScopePolicy
from ..targets.target_inventory import build_inventory, save_inventory


PROVIDER = "subfinder"
NO_SCOPE_REASON = "No scope file provided; scope not enforced"


def _scope_policy(scope_file):
    return ScopePolicy.from_file(scope_file) if scope_file else None


def _evaluate_target(policy, host):
    if policy:
        return policy.evaluate(host)
    return {
        "allowed": True,
        "reason": NO_SCOPE_REASON,
        "matched_rule": "",
        "matched_section": "",
    }


def _add_discovery_metadata(inventory, domain, scope_file=None):
    policy = _scope_policy(scope_file)
    counts = {"in_scope": 0, "out_of_scope": 0}

    inventory["provider"] = PROVIDER
    inventory["domain"] = domain
    inventory["metadata"] = {
        "provider": PROVIDER,
        "domain": domain,
        "scope_file": scope_file,
        "scans_run": 0,
    }

    for item in inventory.get("targets", []):
        evaluation = _evaluate_target(policy, item.get("host", ""))
        in_scope = bool(evaluation["allowed"])
        item["provider"] = PROVIDER
        item["source"] = PROVIDER
        item["in_scope"] = in_scope
        item["scope_reason"] = evaluation.get("reason", "")
        item["matched_rule"] = evaluation.get("matched_rule", "")
        item["matched_section"] = evaluation.get("matched_section", "")
        if in_scope:
            counts["in_scope"] += 1
        else:
            counts["out_of_scope"] += 1

    return counts


def _print_failure(error, output):
    output("ActiveRecon passive subdomain discovery failed")
    output(f"Error: {error}")
    output("Scans run: 0")


def run_discover_command(args, output=print):
    if args.discover_action != "subdomains":
        raise ValueError("discover requires a subcommand: subdomains")

    try:
        config = load_config()
        discovered = run_subfinder(args.domain, config)
        inventory = build_inventory(discovered, source=PROVIDER)
        counts = _add_discovery_metadata(inventory, args.domain, args.scope)
        save_inventory(inventory, args.output)
    except (OSError, RuntimeError, ValueError) as e:
        _print_failure(e, output)
        return 2

    output("ActiveRecon passive subdomain discovery completed")
    output(f"Domain: {args.domain}")
    output(f"Provider: {PROVIDER}")
    output(f"Discovered: {len(inventory['targets'])}")
    output(f"In scope: {counts['in_scope']}")
    output(f"Out of scope: {counts['out_of_scope']}")
    output(f"Output: {args.output}")
    output("Scans run: 0")
    return 0
