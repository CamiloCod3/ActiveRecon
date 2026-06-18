from ..targets.target_diff import diff_inventories
from ..targets.target_inventory import (
    build_inventory,
    export_scope_file,
    load_inventory,
    save_inventory,
)
from ..targets.target_loader import load_targets


def _inventory_host_count(inventory):
    return len({
        item.get("host")
        for item in inventory.get("targets", [])
        if item.get("host")
    })


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
