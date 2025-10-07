---
aliases:
  - "FSE-0002"
cweId: "134"
cweUri: "https://cwe.mitre.org/data/definitions/134.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-30002"
name: "Format String Error"
occurrenceCount: "1"
pluginId: "30002"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "1"
wascId: "6"
---

# Format String Error (Plugin 30002)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/FormatStringScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/FormatStringScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/30002/

### How it detects

Active

## Remediation

Rewrite the background program using proper deletion of bad character strings. This will require a recompile of the background executable.

### References
- https://owasp.org/www-community/attacks/Format_string_attack

## Issues

### GET https://public-firing-range.appspot.com/flashinjection/callbackIsEchoedBack?callback=ZAP%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%25n%25s%0A  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-051e3a2cf7500ff7.md|Issue fin-051e3a2cf7500ff7]]
#### Observations
- [[occurrences/occ-522c1c2e163c0454.md|callbackIsEchoedBack[c]]]

