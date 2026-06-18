from ..policies.scope_policy import ScopePolicy


def run_scope_command(args, output=print):
    if args.scope_action != "check":
        raise ValueError("scope requires a subcommand: check")

    evaluation = ScopePolicy.from_file(args.scope).evaluate(args.target)
    output("ActiveRecon scope check completed")
    output(f"Target: {args.target}")
    output(f"Scope: {args.scope}")
    output(f"Allowed: {'yes' if evaluation['allowed'] else 'no'}")
    output(f"Reason: {evaluation['reason']}")
    output(f"Program: {evaluation.get('program') or 'N/A'}")
    output("Scans run: 0")
    return 0
