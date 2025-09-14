---
aliases:
  - "AC-0020"
cweId: "1021"
cweUri: "https://cwe.mitre.org/data/definitions/1021.html"
generatedAt: "2025-01-01T00:00:00Z"
id: "def-10020"
name: "Missing Anti-clickjacking Header"
occurrenceCount: "1"
pluginId: "10020"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "1"
wascId: "15"
---

# Missing Anti-clickjacking Header (Plugin 10020)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/AntiClickjackingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/AntiClickjackingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10020/

### How it detects

Passive; checks headers: X-Frame-Option; sets evidence; threshold: low

_threshold: low_

Signals:
- header:X-Frame-Option

## Remediation

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### References
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8f698f824b994b04.md|Issue fin-8f698f824b994b04]]
#### Observations
- [[occurrences/occ-56c20b8ec4ba5fd0.md|public-firing-range.appspot.com/[xfo]]]

