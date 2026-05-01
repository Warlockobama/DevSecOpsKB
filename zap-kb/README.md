# zap-kb

zap-kb is the ZAP-focused module of the broader DevSecOps KB project. It fetches OWASP ZAP alerts, converts them into a normalized entities model, and can publish an Obsidian-ready knowledge base.

The module can:
- Fetch alerts from a running ZAP instance or read from a file.
- Normalize data into a stable entities schema for analysis and versioning.
- Enrich definitions with MITRE taxonomy references, estimated CVSS, and optional detection references from ZAP docs/GitHub.
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
- `-include-mitre`: Enrich taxonomy with curated MITRE CWE/CAPEC/ATT&CK metadata (default `true`).
- `-include-cvss`: Estimate definition CVSS from scanner risk when official CVSS is unavailable (default `true`).
- `-detection-details`: `links|summary` (adds brief detection summary when `summary`).
- `-include-traffic`: Attach first/all HTTP request/response snippets.
- `-traffic-scope`: `first|all` and `-traffic-max-bytes` to limit snippet size. Values below 1024 are raised to 1024; High/Critical response bodies are kept in full so analyst evidence is not cut off.
- `-traffic-max-per-issue`: When using `-traffic-scope=first`, enrich up to N occurrences per issue (default 1).
- `-traffic-min-risk`: Only enrich traffic for occurrences at or above this risk (`info|low|medium|high`; default `info`).
- `-traffic-total-max`: Global cap on the number of occurrences to enrich with traffic (default 0 = unlimited).
- `-obsidian-dir`: Output directory when `-format=obsidian` (default `docs/obsidian`).
- `-generated-at`: Override timestamp for stable diffs.
- `-wizard`: Launch the interactive quickstart wizard (enabled by default when no other flags are set and the terminal is interactive).
- `-run-out`: Write a pipeline-friendly run artifact JSON (entities + meta [+alerts]).
- `-run-in`: Read a run artifact (or bare entities JSON) and reuse its entities and labels.
- `-zip-out`: Zip outputs into one artifact (includes `-run-out`, entity/alerts JSON, and Obsidian dir if generated).
- `-redact`: Redact sensitive details in outputs. Comma/space list supported: `domain,query,cookies,auth,headers,body`.
 - Prune-only (vault maintenance): `-prune-scan <label>` deletes occurrence notes in the Obsidian vault matching a `scan.label`, optionally narrowed by `-prune-site <domain label>`. Use `-prune-vault` to target a specific vault; add `-prune-dry-run` to preview.
- Reporting: add `-report-out` to emit a markdown summary from the vault for a time window (default last 30 days when unspecified). Tune with `-report-since`/`-report-until` (RFC3339 or `YYYY-MM-DD`), `-report-lookback` (`30d`, `12w`, `3m`, `1y`), `-report-title`, and `-report-scan` to filter on `scan.label`.

Examples:
- Initialize all known plugin definitions without fetching alerts:
  `go run ./cmd/zap-kb -init -format entities -out docs/data/entities.init.json -all-plugins -include-detection`

- Merge existing entities with fresh alerts:
  `go run ./cmd/zap-kb -format entities -entities-in docs/data/entities.json -out docs/data/entities.json`

- Publish an Obsidian vault:
  `go run ./cmd/zap-kb -format obsidian -entities-in docs/data/entities.json -obsidian-dir docs/obsidian`

- Monthly (or PI) report from the vault:
  `go run ./cmd/zap-kb -run-in out/run.json -format obsidian -obsidian-dir kb-new/obsidian -report-out reports/2025-01.md -report-lookback 30d -report-title "Jan 2025 KB report"`

## Data Model & Behavior (important)
- Findings are deduped per rule+URL+method; occurrences are per alert event. Identical alerts in different scans stay separate because the occurrence ID includes the scan label.
- IDs: finding front matter `id` uses `finding/<findingId>`; occurrence `id` uses `occurrence/<occurrenceId>`.
- Timestamps: `generatedAt` marks build time; occurrences carry `observedAt` (defaults to generatedAt); findings derive `firstSeen`/`lastSeen` from occurrences.
- Status/triage: finding-level `analyst.*` fields are the primary workflow overlay; occurrence data remains scan evidence and roll up to INDEX/DASHBOARD/triage-board.
- Safety: “Next actions” endpoints are neutered (schemes stripped). Use `-redact domain,query,cookies,auth,headers,body,notes` to scrub sensitive data. The `notes` mode clears analyst-authored free text (`analyst.notes`, `analyst.rationale`) and `reproduce.steps[]`, so pasted credentials or PII don't leak into shared exports.
- Helper pages: vault emits `INDEX.md`, `DASHBOARD.md`, `triage-board.md`, `by-domain.md`, and `tuning-candidates.md` (rollup of recurring-FP and `tune-scan`-tagged findings).
- Run artifacts: `-run-out` writes `run.json` (entities + meta + alerts); multiple runs can be merged (`-entities-in`) to build a multi-scan vault.
- Jira/Confluence workflow: medium/high findings auto-export to analyst Jira; low/info findings require the `case-ticket` tag; recurring false positives are surfaced as tuning candidates and can be marked with `tune-scan` for follow-up. Confluence pull does not overwrite workflow unless `pull -confluence-pull-workflow` is explicitly used.
- Detection Epic (optional, `-jira-detection-epic`): creates/reuses one Jira Epic per Definition (idempotent, label-dedup'd) and links each finding ticket via `parent`. Epic summary follows `[ZAP] <alert> (Plugin <id>)`; description carries the detection description, CWE link, ZAP docs link, remediation, and a scan-time evidence rollup (finding/occurrence counts, scan labels, first/last seen, top affected endpoints) so the Epic stands alone as the detection's system-of-record. The Epic key is stored on the Definition as `epicRef` and is surfaced as a "Detection Epic" page property on the Confluence definition page. Override the issue type with `-jira-epic-issue-type` (e.g. `Initiative`) for projects that don't expose Epic. `-jira-component` flows through to Epic components by default; override with `-jira-epic-component` when they should differ.
- Orphan-finding reconciliation: when `-jira-detection-epic` is on, existing finding tickets found via dedup are PUT with the correct `parent` if the Epic link is missing or points elsewhere. Reported as `relinked=N` in the Jira export summary. Safe to re-run; dry-run is skipped.
- Evidence in Jira descriptions: finding tickets render an Evidence section with attack/evidence/param/method from the representative occurrence.
- Live Jira Status/Owner on Confluence: after Jira export, zap-kb pulls each ticket's current status and assignee and writes them into the Confluence finding/occurrence pages so the KB view reflects the live workflow state.
- Recurrence banner: when a previously `fixed` or `accepted` finding reappears in a new scan, Merge flags it with `recurrence` and Confluence renders a prominent advisory panel.
- Per-occurrence analyst note: each Confluence occurrence page carries a marker-delimited "Analyst Note" block that is preserved across re-publishes.
- Per-publish changelog: Confluence finding pages render a collapsible "Changes since last publish" block when the state-sig has shifted (status, owner, risk, Jira status, last seen, or occurrence count). First publishes and no-op publishes omit the block.
- Definition separation: definitions carry `origin` (`tool` or `custom`) so project-owned detections stay distinct from native tool rules.
- Scan-label enforcement: every fresh ingest must be traceable to a run. When `-scan-label` is omitted the CLI retro-labels the run `<source>-<UTC YYYYMMDD-HHMMSS>` and warns; pass an explicit label (e.g. `prod-20260420`) for reproducible runs. Confluence `ExportVault` publishes a top-level "Scans" index page with one row per scan label — first/last seen, distinct findings, distinct definitions, distinct URLs, total occurrences. Legacy unlabeled occurrences bucket under `(unlabeled)` so the gap is visible.
- Finding/definition page property order: finding pages lead with Severity → Confidence → Definition (linked) → CWE → OWASP Top 10 → URL → Method → Occurrences; supplementary fields (WASC, Domain, Last/First Seen, Owner, Analyst Cases, Jira Status, Tags, Source Tool, Scans) follow. Definition pages add an `Open Findings` row and render the Detection row as a human-readable phrase ("Passive scan" rather than "passive"). Finding ID is intentionally not rendered.
- Auth Context on occurrences: Confluence occurrence pages now render an `Auth Context` property (Authenticated/Unauthenticated) derived from captured request headers (Cookie, Authorization Bearer/Basic/Token, X-Csrf/Xsrf/Auth, X-Api-Key). Empty when no headers were captured — never guessed.
- FP guidance on high-volume rules: CDM (10098), CSP (10038), and CDJSF (10017) each carry 4 documented benign scenarios plus an explicit "true positive when…" clause, auto-populated onto Definition pages via `zapmeta.LookupFalsePositiveGuidance` during enrichment.
- MITRE taxonomy and CVSS enrichment are default-on and offline. CWE IDs are expanded to MITRE CWE titles/URLs, CAPEC/ATT&CK IDs are expanded when present, and source attribution is written to the entity. CVSS is marked `devsecopskb-estimated` and derived from the highest scanner risk observed for the definition; existing CVSS values are preserved.
- Enrichment strategy details live in `docs/enrichment-strategy.md`.

## Scripts
PowerShell helper `scripts/kb.ps1` wraps common flows:
- `-Task init` seeds entities (optionally with `-AllPlugins` or `-Plugins`).
- `-Task ingest` fetches alerts from ZAP and merges to entities.
- `-Task publish` writes the Obsidian vault.
- `-Task prune` removes occurrence notes for a given scan label from the Obsidian vault (`-PruneScan`, optional `-PruneSite`).
- `-Task all` runs init → ingest → publish.

Environment variables used by the script:
- `ZAP_URL` (maps to `-zap-url`)
- `ZAP_API_KEY` (maps to `-api-key`)

Python helper `scripts/flatten_report.py` converts ZAP's JSON-plus report (site -> alerts -> instances) into the flat alert list accepted by `zap-kb -in`. It also supports on-the-fly filtering:

```bash
python scripts/flatten_report.py \
  --report /tmp/zap-report.json \
  --out out/alerts.from-report.json \
  --risk high,medium \
  --plugin 40040,90001 \
  --host public-firing-range.appspot.com \
  --url-prefix https://public-firing-range.appspot.com/ \
  --delete-report
```

Flags can be repeated or comma-delimited. Use `--indent 2` for readable JSON or `--limit N` to cap the number of emitted alert instances.

## Data Model
See `docs/schema/entities-v1.md` for the entities schema and how definitions, findings, and occurrences relate.

## Notes
- This repository is part of the "DevSecOps KB"; `zap-kb` is the first module. Additional tools/sections can be added alongside.
- `docs/data/*.json` and `alerts.json` are treated as generated outputs and are ignored by Git by default.
- When publishing to GitHub, consider updating the `module` path in `go.mod` after the repository is created (e.g., `module github.com/<you>/devsecopskb/zap-kb`).

### Dashboard
Publishing (or pruning) also generates `DASHBOARD.md` in the vault with vault‑wide summaries (by scan, severity, domains, and top rules), complementing the workflow-aware `INDEX.md`. The index now highlights issues by status, provides a complete issue list, and includes an occurrence feed alongside the historical scan/domain sections.

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

-4) Triage in Obsidian:
- Open `kb-new/obsidian/INDEX.md` for the workflow-aware run summary (issues by status, severity rollups, and the occurrence feed).
- Drill into definitions → issues → occurrences. Each page has frontmatter:
  - `scan.label`, `domain`, and IDs for linking.
  - Occurrences include request/response snippets (if included) and a ZAP message link when `-zap-base-url` is set.
- Use the “Workflow” section on issue pages for status, notes, and governance.

GitHub Actions workflow `zap-kb-run.yml` is included for manual runs with secrets:
- Set repo secrets: `ZAP_URL`, `ZAP_API_KEY`.
- Run the workflow from the Actions tab; it uploads the Obsidian vault and `entities.json` as artifacts.

Additional automation:
- `zap-kb-smoke.yml` runs a reproducible offline pipeline smoke test from
  `testdata/alerts_smoke.json`; it can optionally hit a live ZAP API when
  `run_live_zap=true` and `ZAP_URL` is configured.
- `zap-kb-release.yml` builds release archives for Linux, macOS, and Windows.
  Push a `v*` tag to publish a GitHub release; run it manually to produce
  workflow artifacts without publishing a release.

## License
- Code: Apache-2.0 (see repository root `LICENSE`).
- Docs/KB content: CC BY 4.0 (see `docs/LICENSE` and `kb-new/obsidian/LICENSE`).
- Examples: CC0 (see `docs/examples/LICENSE`).

See repository `NOTICE` for attribution and trademark notes. Contributions require DCO sign‑off (see `CONTRIBUTING.md`).

