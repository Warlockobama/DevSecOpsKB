---
aliases:
  - "IDSC-0027"
cweId: "615"
cweUri: "https://cwe.mitre.org/data/definitions/615.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10027"
name: "Information Disclosure - Suspicious Comments"
occurrenceCount: "2"
pluginId: "10027"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "2"
wascId: "13"
---

# Information Disclosure - Suspicious Comments (Plugin 10027)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureSuspiciousCommentsScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureSuspiciousCommentsScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10027/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:/\\*.*?\\*/
  - hint: Regular expression; see pattern for details.
- regex://.*
  - hint: Regular expression; see pattern for details.

## Remediation

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

## Issues

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f83236e0a5c84d30.md|Issue fin-f83236e0a5c84d30]]
#### Observations
- [[occurrences/occ-b03b5c5ee87646b4.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5e85daa16f2e99b8.md|Issue fin-5e85daa16f2e99b8]]
#### Observations
- [[occurrences/occ-2f1a9d02f9e113b8.md|OtherParameter]]

