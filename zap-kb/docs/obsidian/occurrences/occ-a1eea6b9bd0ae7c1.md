---
aliases:
  - "UAF parameter-e7c1"
attack: "msnbot/1.1 (+http://search.msn.com/msnbot.htm)"
confidence: "Medium"
definitionId: "def-10104"
domain: "public-firing-range.appspot.com"
findingId: "fin-ca6ab1581b936359"
generatedAt: "2025-09-21T20:00:10Z"
host: "public-firing-range.appspot.com"
id: "occ-a1eea6b9bd0ae7c1"
issueId: "fin-ca6ab1581b936359"
kind: "observation"
method: "GET"
observationId: "occ-a1eea6b9bd0ae7c1"
observedAt: "2025-09-21T20:00:10Z"
param: "Header User-Agent"
path: "/redirect/parameter"
queryKeys: "url"
risk: "Informational"
riskId: "0"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceId: "1"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/redirect/parameter?url=/"
---

# Observation occ-a1eea6b9bd0ae7c1 — UAF parameter-e7c1

> [!Note]
> Risk: Informational () — Confidence: Medium

- Definition: [[definitions/10104-user-agent-fuzzer.md|def-10104]]
- Issue: [[findings/fin-ca6ab1581b936359.md|fin-ca6ab1581b936359]]

**Endpoint:** GET https://public-firing-range.appspot.com/redirect/parameter?url=/

## Rule summary

- Title: User Agent Fuzzer (Plugin 10104)
  - https://owasp.org/wstg

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /redirect/parameter
- Query keys: url

**Param:** Header User-Agent

**Attack:** `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`

## Repro (curl)

```bash
curl "https://public-firing-range.appspot.com/redirect/parameter?url=/"
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
