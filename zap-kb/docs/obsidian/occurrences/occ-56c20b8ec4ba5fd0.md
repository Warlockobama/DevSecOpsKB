---
aliases:
  - "AC public-firing-range.appspot.com-5fd0"
confidence: "Medium"
definitionId: "def-10020"
domain: "public-firing-range.appspot.com"
findingId: "fin-8f698f824b994b04"
generatedAt: "2025-01-01T00:00:00Z"
host: "public-firing-range.appspot.com"
id: "occ-56c20b8ec4ba5fd0"
issueId: "fin-8f698f824b994b04"
kind: "observation"
method: "GET"
observationId: "occ-56c20b8ec4ba5fd0"
observedAt: "2025-01-01T00:00:00Z"
param: "x-frame-options"
path: "/"
risk: "Medium"
riskId: "2"
schemaVersion: "v1"
sourceId: "3"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/"
---

# Observation occ-56c20b8ec4ba5fd0 — AC public-firing-range.appspot.com-5fd0

> [!Info]
> Risk: Medium () — Confidence: Medium

- Definition: [[definitions/10020-missing-anti-clickjacking-header.md|def-10020]]
- Issue: [[findings/fin-8f698f824b994b04.md|fin-8f698f824b994b04]]

**Endpoint:** GET https://public-firing-range.appspot.com/

## Rule summary

- Title: Missing Anti-clickjacking Header (Plugin 10020)
- WASC: 15
- CWE: 1021
- CWE URI: https://cwe.mitre.org/data/definitions/1021.html
- Remediation: Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /

**Param:** x-frame-options

## Repro (curl)

```bash
curl "https://public-firing-range.appspot.com/"
```

## Triage guidance

- Confirm X-Frame-Options or CSP frame-ancestors is present.
- Decide SAMEORIGIN vs DENY; prefer frame-ancestors in CSP for modern browsers.

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
