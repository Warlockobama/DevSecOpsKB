---
aliases:
  - "IDIBS index-74ff"
confidence: "High"
definitionId: "def-120000"
domain: "www.google.com"
findingId: "fin-a9423f04c5999339"
generatedAt: "2025-01-01T00:00:00Z"
host: "www.google.com"
id: "occ-a70fd58cf6a574ff"
issueId: "fin-a9423f04c5999339"
kind: "observation"
method: "GET"
observationId: "occ-a70fd58cf6a574ff"
observedAt: "2025-01-01T00:00:00Z"
param: "_grecaptcha"
path: "/sorry/index"
queryKeys: "continue, q"
risk: "Informational"
riskId: "0"
schemaVersion: "v1"
sourceId: "3"
sourceTool: "zap"
url: "https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dfiring%2Brange%2Bappspot%2Bgoogle%26sei%3D1YacaIjPJJPZ5NoPjJeowAY&q=EgSB3gKOGNaN8sQGIjCFSCeM0u9S-7on-GEdGlp-Ew3dmmCNrLA9xJYvRVI2IklgWlDfnCj8DKapVWJqXccyAVJaAUM"
---

# Observation occ-a70fd58cf6a574ff — IDIBS index-74ff

> [!Note]
> Risk: Informational () — Confidence: High

- Definition: [[definitions/120000-information-disclosure-information-in-browser-sessionstorage.md|def-120000]]
- Issue: [[findings/fin-a9423f04c5999339.md|fin-a9423f04c5999339]]

**Endpoint:** GET https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dfiring%2Brange%2Bappspot%2Bgoogle%26sei%3D1YacaIjPJJPZ5NoPjJeowAY&q=EgSB3gKOGNaN8sQGIjCFSCeM0u9S-7on-GEdGlp-Ew3dmmCNrLA9xJYvRVI2IklgWlDfnCj8DKapVWJqXccyAVJaAUM

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

**Param:** _grecaptcha

## Repro (curl)

```bash
curl "https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dfiring%2Brange%2Bappspot%2Bgoogle%26sei%3D1YacaIjPJJPZ5NoPjJeowAY&q=EgSB3gKOGNaN8sQGIjCFSCeM0u9S-7on-GEdGlp-Ew3dmmCNrLA9xJYvRVI2IklgWlDfnCj8DKapVWJqXccyAVJaAUM"
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
