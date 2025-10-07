# zap-kb

zap-kb is the ZAP-focused module of the broader DevSecOps KB project. It fetches OWASP ZAP alerts, converts them into a normalized entities model, and can publish an Obsidian-ready knowledge base.

The module can:
- Fetch alerts from a running ZAP instance or read from a file.
- Normalize data into a stable entities schema for analysis and versioning.
- Enrich definitions with detection references from ZAP docs/GitHub.
- Publish an Obsidian vault with findings, occurrences, and definitions.

## Quick Start
1. Install Go: https://golang.org/dl/
2. From the `zap-kb` directory:
   - Run: `go run ./cmd/zap-kb -format entities -out docs/data/entities.json`
   - Or use the PowerShell helper: `./scripts/kb.ps1 -Task all`

## CLI Overview
`go run ./cmd/zap-kb [flags]`

Key flags:
- `-format`: `entities|flat|both|obsidian` (default `entities`).
- `-out`: Output path for JSON (`docs/data/alerts.json` for flat; entities path when `-format=entities`).
- `-zap-url`: ZAP API base URL (default `http://127.0.0.1:8090`).
- `-api-key`: ZAP API key (if required).
- `-baseurl`: Filter alerts by base URL.
- `-count`: Limit number of alerts fetched.
- `-in`: Read alerts from a JSON file instead of ZAP.
- `-entities-in`: Merge/enrich from an existing entities JSON.
- `-init`: Initialize KB without fetching alerts (definitions only).
- `-plugins`: Comma/space list of plugin IDs to seed/update definitions.
- `-all-plugins`: Discover all plugin IDs and seed/update definitions.
- `-include-detection`: Enrich definitions with detection links.
- `-detection-details`: `links|summary` (adds brief detection summary when `summary`).
- `-include-traffic`: Attach first/all HTTP request/response snippets.
- `-traffic-scope`: `first|all` and `-traffic-max-bytes` to limit snippet size.
- `-traffic-max-per-issue`: When using `-traffic-scope=first`, enrich up to N observations per issue (default 1).
- `-traffic-min-risk`: Only enrich traffic for observations at or above this risk (`info|low|medium|high`; default `info`).
- `-traffic-total-max`: Global cap on the number of observations to enrich with traffic (default 0 = unlimited).
- `-obsidian-dir`: Output directory when `-format=obsidian` (default `docs/obsidian`).
- `-generated-at`: Override timestamp for stable diffs.
- `-wizard`: Launch the interactive quickstart wizard (enabled by default when no other flags are set and the terminal is interactive).
- `-run-out`: Write a pipeline-friendly run artifact JSON (entities + meta [+alerts]).
- `-run-in`: Read a run artifact (or bare entities JSON) and reuse its entities and labels.
- `-zip-out`: Zip outputs into one artifact (includes `-run-out`, entity/alerts JSON, and Obsidian dir if generated).
- `-redact`: Redact sensitive details in outputs. Comma/space list supported: `domain,query,cookies,auth,headers,body`.
 - Prune-only (vault maintenance): `-prune-scan <label>` deletes occurrence notes in the Obsidian vault matching a `scan.label`, optionally narrowed by `-prune-site <domain label>`. Use `-prune-vault` to target a specific vault; add `-prune-dry-run` to preview.

Examples:
- Initialize all known plugin definitions without fetching alerts:
  `go run ./cmd/zap-kb -init -format entities -out docs/data/entities.init.json -all-plugins -include-detection`

- Merge existing entities with fresh alerts:
  `go run ./cmd/zap-kb -format entities -entities-in docs/data/entities.json -out docs/data/entities.json`

- Publish an Obsidian vault:
  `go run ./cmd/zap-kb -format obsidian -entities-in docs/data/entities.json -obsidian-dir docs/obsidian`

## Scripts
PowerShell helper `scripts/kb.ps1` wraps common flows:
- `-Task init` seeds entities (optionally with `-AllPlugins` or `-Plugins`).
- `-Task ingest` fetches alerts from ZAP and merges to entities.
- `-Task publish` writes the Obsidian vault.
- `-Task prune` removes observation notes for a given scan label from the Obsidian vault (`-PruneScan`, optional `-PruneSite`).
- `-Task all` runs init → ingest → publish.

Environment variables used by the script:
- `ZAP_URL` (maps to `-zap-url`)
- `ZAP_API_KEY` (maps to `-api-key`)

## Data Model
See `docs/schema/entities-v1.md` for the entities schema and how definitions, findings, and occurrences relate.

## Notes
- This repository is part of the "DevSecOps KB"; `zap-kb` is the first module. Additional tools/sections can be added alongside.
- `docs/data/*.json` and `alerts.json` are treated as generated outputs and are ignored by Git by default.
- When publishing to GitHub, consider updating the `module` path in `go.mod` after the repository is created (e.g., `module github.com/<you>/devsecopskb/zap-kb`).

### Dashboard
Publishing (or pruning) also generates `DASHBOARD.md` in the vault with vault‑wide summaries (by scan, severity, domains, and top rules), complementing `INDEX.md` which focuses on the current run plus a brief historical view.

## CI Integration
There are two ways to populate the KB in a pipeline after your ZAP stage:

- Online (recommended): connect to the running ZAP instance via API and fetch alerts directly.
  - Provide `ZAP_URL` and (if required) `ZAP_API_KEY` as environment variables or CI secrets.
  - Example (Ubuntu runner):
    - `go run ./cmd/zap-kb -format entities -out docs/data/entities.json -zap-url "$ZAP_URL" -api-key "$ZAP_API_KEY" -include-traffic -traffic-scope first -include-detection -detection-details summary -scan-label "run $GITHUB_RUN_NUMBER"`
    - `go run ./cmd/zap-kb -format obsidian -entities-in docs/data/entities.json -obsidian-dir kb-new/obsidian -zap-base-url "$ZAP_URL" -scan-label "run $GITHUB_RUN_NUMBER"`

- Offline: import alerts from a JSON file produced by your ZAP step (`-in` flag).
  - Example: `go run ./cmd/zap-kb -in ./zap-alerts.json -format entities -out docs/data/entities.json`
  - Then publish Obsidian as above using `-entities-in`.

### Python helper (CI-friendly)

If you prefer to orchestrate the KB import from Python, run `python zap-kb/scripts/zap_run_artifact.py`. The helper wraps the Go CLI, strips raw alerts by default, and exposes flags to tune traffic capture for CI pipelines.

Example (offline alerts JSON):

```bash
python zap-kb/scripts/zap_run_artifact.py \
  --alerts-json out/alerts.json \
  --artifact out/run.json \
  --scan-label "$RUN_ID@$BRANCH" \
  --zip-archive out/kb-run.zip \
  --include-traffic --traffic-scope first --traffic-max-bytes 4096
```

Use `--keep-alerts` if raw alerts are needed for auditing, and `--entities-out` to persist the intermediate entities JSON.
### Run Artifact (recommended for portability)
To keep pipeline runs self-contained and reproducible, export a single artifact that
captures the normalized entities and run metadata:

- Produce: `go run ./cmd/zap-kb -format entities -out docs/data/entities.json -run-out run.json -scan-label "$RUN_ID@$BRANCH" -zap-url "$ZAP_URL" -api-key "$ZAP_API_KEY"`
- Ingest later: `go run ./cmd/zap-kb -run-in run.json -format obsidian -obsidian-dir kb-new/obsidian`

Notes:
- `-run-in` accepts both the wrapper `run.json` and a bare `entities.json` for convenience.
- When present, run metadata (scan/site labels, zap-base) is applied to Obsidian output.
- To ship a single file from your pipeline, add `-zip-out out/run.zip`.
- Use `-redact domain,cookies,auth` if your artifacts leave the build network.

## End-to-end: Initialize → Update → Triage
1) Initialize KB definitions (no alerts yet):
- Seed all known ZAP plugin definitions with detection links and summaries:
  - `go run ./cmd/zap-kb -init -format entities -out docs/data/entities.init.json -all-plugins -include-detection -detection-details summary`
  - Optional: publish initial vault: `-format obsidian -entities-in docs/data/entities.init.json -obsidian-dir kb-new/obsidian`

2) Run ZAP in your pipeline and produce a portable artifact:
- Online mode (ZAP reachable):
  - `go run ./cmd/zap-kb -format entities -out out/entities.json -zap-url "$ZAP_URL" -api-key "$ZAP_API_KEY" -baseurl "$TARGET_BASE" -include-traffic -traffic-scope first -include-detection -detection-details summary -scan-label "$RUN_ID@$BRANCH" -redact domain,cookies,auth -run-out out/run.json -zip-out out/kb.zip`
- Offline mode (alerts exported to file):
  - `go run ./cmd/zap-kb -in out/alerts.json -format entities -out out/entities.json -scan-label "$RUN_ID@$BRANCH" -redact domain,cookies -run-out out/run.json -zip-out out/kb.zip`

3) Import into the KB and publish for triage (can be a separate job or on your workstation):
- `go run ./cmd/zap-kb -run-in out/run.json -format obsidian -obsidian-dir kb-new/obsidian -site-label "MyApp" -zap-base-url "$ZAP_URL"`

4) Triage in Obsidian:
- Open `kb-new/obsidian/INDEX.md` for a run summary (status and severity rollups).
- Drill into definitions → issues → observations. Each page has frontmatter:
  - `scan.label`, `domain`, and IDs for linking.
  - Observations include request/response snippets (if included) and a ZAP message link when `-zap-base-url` is set.
- Use the “Workflow” section on issue pages for status, notes, and governance.

GitHub Actions workflow `zap-kb-run.yml` is included for manual runs with secrets:
- Set repo secrets: `ZAP_URL`, `ZAP_API_KEY`.
- Run the workflow from the Actions tab; it uploads the Obsidian vault and `entities.json` as artifacts.

## License
- Code: Apache-2.0 (see repository root `LICENSE`).
- Docs/KB content: CC BY 4.0 (see `docs/LICENSE` and `kb-new/obsidian/LICENSE`).
- Examples: CC0 (see `docs/examples/LICENSE`).

See repository `NOTICE` for attribution and trademark notes. Contributions require DCO sign‑off (see `CONTRIBUTING.md`).

