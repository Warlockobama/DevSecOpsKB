---
aliases:
  - "OSR-0028"
cweId: "601"
cweUri: "https://cwe.mitre.org/data/definitions/601.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10028"
name: "Off-site Redirect"
occurrenceCount: "1"
pluginId: "10028"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "1"
wascId: "38"
---

# Off-site Redirect (Plugin 10028)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledOpenRedirectScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledOpenRedirectScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10028/

### How it detects

Passive

## Remediation

To avoid the open redirect vulnerability, parameters of the application script/program must be validated before sending 302 HTTP code (redirect) to the client browser. Implement safe redirect functionality that only redirects to relative URI's, or a list of trusted domains.

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/601.html

## Issues

### GET https://public-firing-range.appspot.com/urldom/redirect?url=http://example.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c1b50d2d032dc2e.md|Issue fin-0c1b50d2d032dc2e]]
#### Observations
- [[occurrences/occ-8d26c7fc7823cf8b.md|redirect[u]]]

