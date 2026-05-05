# Enrichment Strategy

The KB enrichment path is deterministic by default. It should improve triage
context without making normal CI runs depend on live third-party catalog
downloads.

## Default Enrichment

Default-on enrichments run after normalization and merge:

- `EnrichTaxonomy`: fills missing CWE from known ZAP metadata, then derives
  OWASP Top 10 and CAPEC IDs from curated local maps.
- `EnrichMITRE`: expands existing CWE, CAPEC, and ATT&CK IDs with curated
  MITRE titles, canonical URLs, source attribution, and mapping confidence.
- `EnrichCVSS`: estimates definition-level CVSS from the highest observed
  scanner risk when no CVSS is already present.

These can be disabled with `-include-mitre=false` or `-include-cvss=false`.

## CVSS Policy

Scanner alerts usually describe weakness classes, not CVEs. The KB therefore
does not present estimated CVSS as authoritative. Estimated scores must include:

- `source=devsecopskb-estimated`
- a rationale explaining that the score was derived from scanner risk
- the CVSS vector and version used for repeatability

Existing CVSS values are never overwritten. If an official advisory or analyst
score exists, it remains the source of truth.

## MITRE Policy

MITRE enrichment is a local, curated expansion of identifiers that are already
present or derived from existing CWE mappings. It does not infer broad ATT&CK
techniques from CWE alone. ATT&CK techniques are expanded only when a technique
ID is already present in taxonomy, such as project-owned custom detection
mappings.

## Official Catalog Refresh

Normal KB publish runs stay offline and deterministic. Official MITRE data is
refreshed explicitly through taxonomy maintenance commands, then reviewed before
runtime enrichment consumes it.

Current command support:

```powershell
go run ./cmd/zap-kb taxonomy audit -entities-in docs/data/entities.json
go run ./cmd/zap-kb taxonomy update -source attack -out docs/data/attack-techniques.json
go run ./cmd/zap-kb taxonomy update -source cwe -out docs/data/cwe-cache.json
go run ./cmd/zap-kb taxonomy update -source capec -out docs/data/capec-cache.json
go run ./cmd/zap-kb taxonomy suggest-capec -entities-in docs/data/entities.json -capec-cache docs/data/capec-cache.json
```

The ATT&CK update command reads the public MITRE ATT&CK STIX bundle and writes a
local technique cache with IDs, names, URLs, and tactics. The CWE update command
reads MITRE's current CWE XML ZIP and records weakness IDs, names, URLs, status,
and related weakness IDs. The CAPEC update command reads MITRE's current CAPEC
XML and records attack pattern IDs, names, URLs, status, and related CWE IDs.
`suggest-capec` reports candidate mappings from official CAPEC related-CWE data.
Mapping decisions should remain explicit and testable on top of these caches.

Stored taxonomy keeps both compatibility and rich fields:

- compatibility fields: `cweid`, `cweUri`, `capecIds`, `attack`
- rich fields: `cweName`, `capec`, `attackTechniques`,
  `mappingConfidence`, `sources`

## Adapter Boundary

Live adapters for NVD, EPSS, OSV, MITRE catalog downloads, or vendor advisories
should feed the same entity fields. They should not replace the offline path;
CI and local smoke tests must continue to work without network access.
