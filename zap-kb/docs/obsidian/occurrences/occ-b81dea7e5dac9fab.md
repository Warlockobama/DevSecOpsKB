---
aliases:
  - "ISIAS public-firing-range.appspot.com-9fab"
confidence: "Medium"
definitionId: "def-90004"
domain: "public-firing-range.appspot.com"
findingId: "fin-704a20766eb64da8"
generatedAt: "2025-01-01T00:00:00Z"
host: "public-firing-range.appspot.com"
id: "occ-b81dea7e5dac9fab"
issueId: "fin-704a20766eb64da8"
kind: "observation"
method: "GET"
observationId: "occ-b81dea7e5dac9fab"
observedAt: "2025-01-01T00:00:00Z"
param: "Cross-Origin-Resource-Policy"
path: "/"
risk: "Low"
riskId: "1"
schemaVersion: "v1"
sourceId: "3"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/"
---

# Observation occ-b81dea7e5dac9fab — ISIAS public-firing-range.appspot.com-9fab

> [!Note]
> Risk: Low () — Confidence: Medium

- Definition: [[definitions/90004-insufficient-site-isolation-against-spectre-vulnerability.md|def-90004]]
- Issue: [[findings/fin-704a20766eb64da8.md|fin-704a20766eb64da8]]

**Endpoint:** GET https://public-firing-range.appspot.com/

## Rule summary

- Title: Insufficient Site Isolation Against Spectre Vulnerability (Plugin 90004)
- WASC: 14
- CWE: 693
- CWE URI: https://cwe.mitre.org/data/definitions/693.html
- Remediation: Ensure that the application/web server sets the Cross-Origin-Embedder-Policy header appropriately, and that it sets the Cross-Origin-Embedder-Policy header to 'require-corp' for documents.
If possible, ensure that the end user uses a standards-compliant and modern web browser that supports the Cross-Origin-Embedder-Policy header (https://caniuse.com/mdn-http_headers_cross-origin-embedder-policy).
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /

**Param:** Cross-Origin-Resource-Policy

## Repro (curl)

```bash
curl "https://public-firing-range.appspot.com/"
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
