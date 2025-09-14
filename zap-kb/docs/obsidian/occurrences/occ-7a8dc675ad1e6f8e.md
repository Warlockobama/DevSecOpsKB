---
aliases:
  - "RECCD public-firing-range.appspot.com-6f8e"
confidence: "Low"
definitionId: "def-10015"
domain: "public-firing-range.appspot.com"
evidence: "public, max-age=600"
findingId: "fin-2c7883f2fe944556"
generatedAt: "2025-01-01T00:00:00Z"
host: "public-firing-range.appspot.com"
id: "occ-7a8dc675ad1e6f8e"
issueId: "fin-2c7883f2fe944556"
kind: "observation"
method: "GET"
observationId: "occ-7a8dc675ad1e6f8e"
observedAt: "2025-01-01T00:00:00Z"
param: "cache-control"
path: "/"
risk: "Informational"
riskId: "0"
schemaVersion: "v1"
sourceId: "3"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/"
---

# Observation occ-7a8dc675ad1e6f8e — RECCD public-firing-range.appspot.com-6f8e

> [!Note]
> Risk: Informational () — Confidence: Low

- Definition: [[definitions/10015-re-examine-cache-control-directives.md|def-10015]]
- Issue: [[findings/fin-2c7883f2fe944556.md|fin-2c7883f2fe944556]]

**Endpoint:** GET https://public-firing-range.appspot.com/

## Rule summary

- Title: Re-examine Cache-control Directives (Plugin 10015)
- WASC: 13
- CWE: 525
- CWE URI: https://cwe.mitre.org/data/definitions/525.html
- Remediation: For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /

**Param:** cache-control

## Evidence

```
public, max-age=600
```

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
