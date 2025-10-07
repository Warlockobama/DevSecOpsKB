---
aliases:
  - "AED-0022"
cweId: "550"
cweUri: "https://cwe.mitre.org/data/definitions/550.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-90022"
name: "Application Error Disclosure"
occurrenceCount: "1"
pluginId: "90022"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "1"
wascId: "13"
---

# Application Error Disclosure (Plugin 90022)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ApplicationErrorScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ApplicationErrorScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90022/

### How it detects

Passive; sets evidence; threshold: high

_threshold: high_

## Remediation

Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.

## Issues

### GET https://public-firing-range.appspot.com/reflected/parameter/body/500?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f7f0be74cb5a3116.md|Issue fin-f7f0be74cb5a3116]]
#### Observations
- [[occurrences/occ-7ea89348ef945f1b.md|500]]

