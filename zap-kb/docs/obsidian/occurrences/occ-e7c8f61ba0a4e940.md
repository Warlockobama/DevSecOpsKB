---
aliases:
  - "UAF leakedcookie-e940"
attack: "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"
confidence: "Medium"
definitionId: "def-10104"
domain: "public-firing-range.appspot.com"
findingId: "fin-c1ff9e373d2ef805"
generatedAt: "2025-09-21T20:00:10Z"
host: "public-firing-range.appspot.com"
id: "occ-e7c8f61ba0a4e940"
issueId: "fin-c1ff9e373d2ef805"
kind: "observation"
method: "GET"
observationId: "occ-e7c8f61ba0a4e940"
observedAt: "2025-09-21T20:00:10Z"
param: "Header User-Agent"
path: "/leakedcookie/leakedcookie"
risk: "Informational"
riskId: "0"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceId: "1"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/leakedcookie/leakedcookie"
---

# Observation occ-e7c8f61ba0a4e940 — UAF leakedcookie-e940

> [!Note]
> Risk: Informational () — Confidence: Medium

- Definition: [[definitions/10104-user-agent-fuzzer.md|def-10104]]
- Issue: [[findings/fin-c1ff9e373d2ef805.md|fin-c1ff9e373d2ef805]]

**Endpoint:** GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie

## Rule summary

- Title: User Agent Fuzzer (Plugin 10104)
  - https://owasp.org/wstg

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /leakedcookie/leakedcookie

**Param:** Header User-Agent

**Attack:** `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`

## Repro (curl)

```bash
curl "https://public-firing-range.appspot.com/leakedcookie/leakedcookie"
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
