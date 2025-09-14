---
aliases:
  - "IDIBS search-b009"
confidence: "High"
definitionId: "def-120000"
domain: "www.google.com"
findingId: "fin-72c38c803671c7d9"
generatedAt: "2025-01-01T00:00:00Z"
host: "www.google.com"
id: "occ-cbe27f6d32dbb009"
issueId: "fin-72c38c803671c7d9"
kind: "observation"
method: "GET"
observationId: "occ-cbe27f6d32dbb009"
observedAt: "2025-01-01T00:00:00Z"
param: "hsb;;1755088609281"
path: "/search"
queryKeys: "client, q, sei"
risk: "Informational"
riskId: "0"
schemaVersion: "v1"
sourceId: "3"
sourceTool: "zap"
url: "https://www.google.com/search?client=firefox-b-d&q=firing+range+appspot+google&sei=1YacaIjPJJPZ5NoPjJeowAY"
---

# Observation occ-cbe27f6d32dbb009 — IDIBS search-b009

> [!Note]
> Risk: Informational () — Confidence: High

- Definition: [[definitions/120000-information-disclosure-information-in-browser-sessionstorage.md|def-120000]]
- Issue: [[findings/fin-72c38c803671c7d9.md|fin-72c38c803671c7d9]]

**Endpoint:** GET https://www.google.com/search?client=firefox-b-d&q=firing+range+appspot+google&sei=1YacaIjPJJPZ5NoPjJeowAY

## Rule summary

- Title: Information Disclosure - Information in Browser sessionStorage (Plugin 120000)
- WASC: 13
- CWE: 359
- CWE URI: https://cwe.mitre.org/data/definitions/359.html
- Remediation: This is an informational alert and no action is necessary.

## Endpoint details

- Scheme: https
- Host: www.google.com
- Path: /search
- Query keys: client, q, sei

**Param:** hsb;;1755088609281

## Repro (curl)

```bash
curl "https://www.google.com/search?client=firefox-b-d&q=firing+range+appspot+google&sei=1YacaIjPJJPZ5NoPjJeowAY"
```

## Triage guidance

- Validate the finding manually and confirm exploitability in this context.
- Document false-positive conditions and add ignores where appropriate.

## Workflow

- Status: open

### Checklist

- [ ] Triage
- [ ] Validate
- [ ] File ticket
- [ ] Fix verified
- [ ] Close

### Governance

- False positive reason: 
- Acceptance justification: 
- Acceptance expires at (UTC): 
- Due at (UTC): 
