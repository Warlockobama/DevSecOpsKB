---
aliases:
  - "UAF NOSTARTSWITHJS-aa0e"
attack: "Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4"
confidence: "Medium"
definitionId: "def-10104"
domain: "public-firing-range.appspot.com"
findingId: "fin-ece6931d280c6e37"
generatedAt: "2025-09-21T20:00:10Z"
host: "public-firing-range.appspot.com"
id: "occ-e88bfb48d311aa0e"
issueId: "fin-ece6931d280c6e37"
kind: "observation"
method: "GET"
observationId: "occ-e88bfb48d311aa0e"
observedAt: "2025-09-21T20:00:10Z"
param: "Header User-Agent"
path: "/redirect/parameter/NOSTARTSWITHJS"
queryKeys: "url"
risk: "Informational"
riskId: "0"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceId: "1"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/redirect/parameter/NOSTARTSWITHJS?url=/"
---

# Observation occ-e88bfb48d311aa0e — UAF NOSTARTSWITHJS-aa0e

> [!Note]
> Risk: Informational () — Confidence: Medium

- Definition: [[definitions/10104-user-agent-fuzzer.md|def-10104]]
- Issue: [[findings/fin-ece6931d280c6e37.md|fin-ece6931d280c6e37]]

**Endpoint:** GET https://public-firing-range.appspot.com/redirect/parameter/NOSTARTSWITHJS?url=/

## Rule summary

- Title: User Agent Fuzzer (Plugin 10104)
  - https://owasp.org/wstg

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /redirect/parameter/NOSTARTSWITHJS
- Query keys: url

**Param:** Header User-Agent

**Attack:** `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`

## Repro (curl)

```bash
curl "https://public-firing-range.appspot.com/redirect/parameter/NOSTARTSWITHJS?url=/"
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
