---
aliases:
  - "IDIBS index-e338"
confidence: "High"
definitionId: "def-120000"
domain: "www.google.com"
findingId: "fin-b27160be4428583e"
generatedAt: "2025-09-21T20:00:10Z"
host: "www.google.com"
id: "occ-bbbc9fa843cbe338"
issueId: "fin-b27160be4428583e"
kind: "observation"
method: "GET"
observationId: "occ-bbbc9fa843cbe338"
observedAt: "2025-09-21T20:00:10Z"
param: "rc::c"
path: "/sorry/index"
queryKeys: "continue, q"
risk: "Informational"
riskId: "0"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceId: "3"
sourceTool: "zap"
url: "https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dgoogle%2Bfiring%2Brange%26sei%3Dj_jJaNXSKOmMwbkP-Je1uAY&q=EgSB3qOYGJDxp8YGIjDveYUWABxXj37Uckg8e5nyxzUCm3Hoex3ej7Ur3nbuOglgQJYhcGkp8XUuNILWJFQyAVJaAUM"
---

# Observation occ-bbbc9fa843cbe338 — IDIBS index-e338

> [!Note]
> Risk: Informational () — Confidence: High

- Definition: [[definitions/120000-information-disclosure-information-in-browser-sessionstorage.md|def-120000]]
- Issue: [[findings/fin-b27160be4428583e.md|fin-b27160be4428583e]]

**Endpoint:** GET https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dgoogle%2Bfiring%2Brange%26sei%3Dj_jJaNXSKOmMwbkP-Je1uAY&q=EgSB3qOYGJDxp8YGIjDveYUWABxXj37Uckg8e5nyxzUCm3Hoex3ej7Ur3nbuOglgQJYhcGkp8XUuNILWJFQyAVJaAUM

## Rule summary

- Title: Information Disclosure - Information in Browser sessionStorage (Plugin 120000)
- WASC: 13
- CWE: 359
- CWE URI: https://cwe.mitre.org/data/definitions/359.html
- Remediation: This is an informational alert and no action is necessary.

## Endpoint details

- Scheme: https
- Host: www.google.com
- Path: /sorry/index
- Query keys: continue, q

**Param:** rc::c

## Repro (curl)

```bash
curl "https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dgoogle%2Bfiring%2Brange%26sei%3Dj_jJaNXSKOmMwbkP-Je1uAY&q=EgSB3qOYGJDxp8YGIjDveYUWABxXj37Uckg8e5nyxzUCm3Hoex3ej7Ur3nbuOglgQJYhcGkp8XUuNILWJFQyAVJaAUM"
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
