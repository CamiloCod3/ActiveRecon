# Scope Examples

These examples are safe scope-policy examples for local labs and documentation.

Only scan systems you own or control.

The `example.com` values are documentation-only examples and are not bug bounty targets.

## Check A Scope

```bash
python -m activerecon.main scope check --target api.example.com --scope docs/examples/scopes/example_program_scope.json
```

```bash
python -m activerecon.main scope check \
  --target admin.example.com \
  --scope docs/examples/scopes/example_program_scope.json
```

Scope checks do not run scans.

## Local Lab Dry Run

```bash
python -m activerecon.main \
  --target 127.0.0.1 \
  --scope docs/examples/scopes/local_lab_scope.json \
  --scan-profile web \
  --dry-run
```

The local lab scope allows `127.0.0.1`, `localhost`, and `http://127.0.0.1:3000/` for local OWASP Juice Shop testing.
