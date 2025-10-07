---
aliases:
  - "UCJEX-0043"
cweId: "20"
cweUri: "https://cwe.mitre.org/data/definitions/20.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10043"
name: "User Controllable JavaScript Event (XSS)"
occurrenceCount: "3"
pluginId: "10043"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "3"
wascId: "20"
---

# User Controllable JavaScript Event (XSS) (Plugin 10043)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledJavascriptEventScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledJavascriptEventScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10043/

### How it detects

Passive; checks headers: Content-Type

Signals:
- header:Content-Type

## Remediation

Validate all input and sanitize output it before writing to any Javascript on* events.

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

## Issues

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f199d12d5d45fb6.md|Issue fin-7f199d12d5d45fb6]]
#### Observations
- [[occurrences/occ-712a9e763f2e51ee.md|DOUBLE_QUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d501b4d6060e846e.md|Issue fin-d501b4d6060e846e]]
#### Observations
- [[occurrences/occ-c4d5dbd477bf7c3a.md|SINGLE_QUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-700d7bfc13a156bc.md|Issue fin-700d7bfc13a156bc]]
#### Observations
- [[occurrences/occ-63a7fecef23d9118.md|UNQUOTED_ATTRIBUTE[q]]]

