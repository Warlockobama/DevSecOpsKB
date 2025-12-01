# zap-kb - AI Instructions (current model)

Purpose
- Normalize ZAP alerts into the entities model (definitions, findings, occurrences) and publish an Obsidian-ready KB (plus optional reports/dashboards).
- Idempotent runs: deduplicate within a run; across runs, scan labels keep occurrences distinct.

Outputs & sources of truth
- Entities JSON: pretty-printed (`-format entities`), default `docs/data/entities.json`.
- Run artifact: `-run-out run.json` (entities + meta + alerts).
- Obsidian vault: `-format obsidian -obsidian-dir <dir>` writes INDEX, DASHBOARD, triage-board, by-domain, and per-item pages.

Fetching
- Default: fetch all alerts (paged) from ZAP API (`-zap-url`, `-api-key` if needed).
- Offline: `-in <alerts.json>` reads flattened alerts.
- Merge/enrich: `-entities-in <entities.json>` merges new alerts into prior entities.

Entity model (v1)
- Definitions: rule metadata (pluginId, alert/name, taxonomy, remediation, detection links).
- Findings: deduped per rule+URL+method (IDs `fin-...`; front matter `id: finding/<id>`).
- Occurrences: every alert event; IDs include scan label (`occ-...`, `id: occurrence/<id>`). Fields include URL/method/param/attack/evidence, `observedAt`, `scan.label`, analyst triage fields, optional traffic snippets.
- Timestamps: `generatedAt` on the set; occurrences carry `observedAt` (defaults to generatedAt); findings derive `firstSeen`/`lastSeen`.

Deduplication
- Within a scan: key = pluginId|url|method|param|riskcode|confidence|attack|evidence.
- Across scans: occurrence IDs include `scan.label`, so identical alerts in different runs stay distinct. Reusing the same scan label collapses them.

Triage persistence
- Regeneration reads existing occurrence front matter first to preserve `analyst.*` fields. Status rollups flow to INDEX, DASHBOARD, triage-board.

Safety & redaction
- “Next actions” endpoints are neutered (no http/https) to avoid live links.
- Redaction: `-redact domain,query,cookies,auth,headers,body` (any subset) to scrub sensitive fields before publishing.

Detection enrichment (optional)
- `-include-detection` adds ZAP docs/GitHub references; `-detection-details summary` adds brief detection summaries/signals when available.
  - logic type (passive/active), add-on name, source path, GitHub link.
  - Populates `definitions[].detection` in Entities and renders a "Detection logic" section in Obsidian.
 - Add `-detection-details summary` to fetch the rule class and produce a brief "How it detects" summary (headers/regex/threshold/strength).

Iteration mode (no API)
- Use `-in file.json` to read ZAP alerts (flat array) from a file and skip API fetch.
- Use `-generated-at RFC3339` to override Entities `generatedAt` for stable diffs during iteration.
- Example (Windows PowerShell):
  - `go run .\cmd\zap-kb -in docs\data\alerts.json -format entities -out docs\data\entities.json -generated-at 2025-01-01T00:00:00Z`

Entities merge + enrich-only
- Use `-entities-in entities.json` to load an existing Entities file for merge/enrichment.
- When `-entities-in` is provided and no alerts are fetched or supplied via `-in`, the tool runs enrichment only (e.g., `-include-detection`, `-include-traffic`).
- To merge newly built entities (from alerts) into an existing Entities file: 
  - `go run .\cmd\zap-kb -in docs\data\alerts.json -format entities -out docs\data\entities.json -entities-in docs\data\entities.json`
- For Obsidian without fetching alerts (enrich-only):
  - `go run .\cmd\zap-kb -format obsidian -obsidian-dir docs\obsidian -entities-in docs\data\entities.json -include-detection`

Add/update definitions by plugin id (no alerts required)
- Use `-plugins` to add stub definitions for specific plugin IDs and enrich detection info:
  - Windows PowerShell: `go run .\cmd\zap-kb -format entities -out docs\data\entities.json -plugins "10020 10038 40012" -include-detection`
  - Or comma-separated: `-plugins 10020,10038,40012`
- Note: Quote the space-separated list so flags after it are parsed correctly.

PowerShell helper (development convenience)
- Script: `zap-kb/scripts/kb.ps1` exposes common tasks:
  - Init all plugin definitions (links): `pwsh -File zap-kb/scripts/kb.ps1 init -AllPlugins`
  - Init with summaries: `pwsh -File zap-kb/scripts/kb.ps1 init -AllPlugins -Detection summary`
  - Ingest ZAP alerts into entities: `pwsh -File zap-kb/scripts/kb.ps1 ingest -ZapUrl http://127.0.0.1:8090 -ApiKey <KEY>`
  - Publish Obsidian from entities: `pwsh -File zap-kb/scripts/kb.ps1 publish`
  - Enrich detection for specific plugins: `pwsh -File zap-kb/scripts/kb.ps1 enrich -Plugins "10020 10038" -Detection summary`

Update all plugins (no alerts required)
- Discover all known plugins from ZAP docs and update every definition:
  - `go run .\\cmd\\zap-kb -format entities -out docs\\data\\entities.json -all-plugins -include-detection -detection-details summary`
- Equivalent shorthand: `-plugins all`.
Init mode (no run data)
- Use `-init` to seed/update the KB without fetching alerts. It creates/updates definitions only (no findings/occurrences).
- Defaults to all plugins when no explicit `-plugins` list is given.
- Examples:
  - `go run ./cmd/zap-kb -init -format entities -out docs/data/entities.json -include-detection`
  - `go run ./cmd/zap-kb -init -format entities -out docs/data/entities.json -plugins "10020 10038" -include-detection -detection-details summary`
