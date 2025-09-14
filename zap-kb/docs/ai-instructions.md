# zap-kb — AI Instructions

Purpose
- Produce a single JSON file of ZAP alert occurrences for downstream use (Obsidian, Confluence, dashboards).
- Idempotent runs: deduplicate within a run and across runs (with -merge).

Source of truth
- Pretty-printed UTF-8 JSON written to -out (default: docs/data/alerts.json).
- Directory is created if missing.

Fetching
- Default: fetch all alerts (paged) from ZAP Desktop API at http://127.0.0.1:8090.
- -count N: fetch first N alerts only.
- Typical run (Windows PowerShell):
  - cd F:\projects\devsecopskb\zap-kb
  - go run .\cmd\zap-kb -zap-url http://127.0.0.1:8090 -api-key <KEY> -out docs\data\alerts.json

JSON shape (current, raw occurrences)
Array of objects with tolerant parsing for numeric fields:
- pluginId (string)
- alert (string)
- name (string)
- risk (string)
- riskcode (string)
- confidence (string)
- url (string)
- method (string)
- param (string)
- attack (string)
- evidence (string)
- other (string)
- solution (string)
- reference (string)
- cweid (int; string/number accepted)
- wascid (int; string/number accepted)
- sourceid (string)

Deduplication
- Always deduplicate before write.
- Optional -merge: load existing file, append new results, dedup, then write.
- Deterministic key (normalized):
  pluginId | url | method | param | riskcode | confidence | attack | evidence
- Implementation: short SHA-1 of the key (stable). Sort output by pluginId, url, param, evidence for reproducibility.
- Console output:
  - Fetched {count} alerts (after dedup)
  - Preview first ~5 lines:
    [0] {alert} | risk={risk} url={url} param={param} plugin={pluginId} cwe={cweid}

Why keep repeated fields today?
- We keep full alert occurrences so the JSON is self-contained and portable without extra joins.
- After the “entity model” phase, we will:
  - Definition (by pluginId + metadata): shared fields (name, solution, references, CWE, etc.).
  - Occurrence: per-endpoint fields (url, method, param, evidence, etc.) plus stable ID.
  - Finding: roll-ups as needed.
- That change will remove duplication while preserving compatibility via a versioned schema.

Stable IDs (future)
- Current dedup uses SHA-1 truncated to 8 bytes as the key.
- We can emit an "occurrenceId" based on:
  - SHA-1(key) hex (existing), or
  - UUIDv5(namespace, key) for standard UUID format.
- Decision: keep internal SHA-1 for dedup now; introduce UUIDv5 in the entity model rollout.

Idempotency expectations
- Running twice against the same ZAP state yields the same JSON (no growth).
- With -merge, only truly new alerts increase the count.

Conventions
- Go 1.21+, no external deps.
- Single CLI execution, minimal logs.
- Pretty JSON, safe for Git.

Future roadmap (do not implement yet)
- Definition/Finding/Occurrence model with deterministic IDs (UUIDv5/ULID).
- Enrichment (taxonomy, normalization, scoring, routing).
- Obsidian Markdown and Confluence sinks.

Detection enrichment (optional)
- Use `-include-detection` to link rules to their ZAP docs and GitHub source.
- Best-effort scrape of https://www.zaproxy.org/docs/alerts/{pluginId}/ to infer:
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
