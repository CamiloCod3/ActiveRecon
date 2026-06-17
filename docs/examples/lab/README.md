# Local Lab Targets

These examples are for local lab targets only.

Only scan systems you own or control. `127.0.0.1` and `localhost` are intended for safe local testing on your own machine.

`http://127.0.0.1:3000/` is intended for OWASP Juice Shop running locally. Juice Shop must be running before scanning port `3000`.

Current scope export is host-based, so an exported scope file will allow the host, not only a specific port or path.

Keep documentation-only targets under `docs/examples/targets/`. Keep local lab scan targets under `docs/examples/lab/`.

## Import Local Lab Targets

```bash
python -m activerecon.main targets import --input docs/examples/lab/local_targets.txt --output inventories/local_lab.json
```

## Export Local Lab Scope

```bash
python -m activerecon.main targets export-scope --inventory inventories/local_lab.json --output scopes/local_lab.txt
```

## Scan Localhost Web Profile

```bash
python -m activerecon.main --target 127.0.0.1 --scope scopes/local_lab.txt --scan-profile web --output local-lab-web
```

## Scan Local Juice Shop

```bash
python -m activerecon.main --target http://127.0.0.1:3000/ --scope scopes/local_lab.txt --scan-profile web --output juice-shop-web
```
