---
aliases:
  - "XCTO public-firing-range.appspot.com-dcc0"
confidence: "Medium"
definitionId: "def-10021"
domain: "public-firing-range.appspot.com"
findingId: "fin-ef75eb3eaa2dcd27"
generatedAt: "2025-01-01T00:00:00Z"
host: "public-firing-range.appspot.com"
id: "occ-717cc6a7f671dcc0"
issueId: "fin-ef75eb3eaa2dcd27"
kind: "observation"
method: "GET"
observationId: "occ-717cc6a7f671dcc0"
observedAt: "2025-01-01T00:00:00Z"
param: "x-content-type-options"
path: "/"
risk: "Low"
riskId: "1"
schemaVersion: "v1"
sourceId: "3"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/"
---

# Observation occ-717cc6a7f671dcc0 — XCTO public-firing-range.appspot.com-dcc0

> [!Note]
> Risk: Low () — Confidence: Medium

- Definition: [[definitions/10021-x-content-type-options-header-missing.md|def-10021]]
- Issue: [[findings/fin-ef75eb3eaa2dcd27.md|fin-ef75eb3eaa2dcd27]]

**Endpoint:** GET https://public-firing-range.appspot.com/

## Rule summary

- Title: X-Content-Type-Options Header Missing (Plugin 10021)
- WASC: 15
- CWE: 693
- CWE URI: https://cwe.mitre.org/data/definitions/693.html
- Remediation: Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
  - https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)
  - https://owasp.org/www-community/Security_Headers

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /

**Param:** x-content-type-options

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
