---
aliases:
  - "SRIA-0003"
cweId: "345"
cweUri: "https://cwe.mitre.org/data/definitions/345.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-90003"
name: "Sub Resource Integrity Attribute Missing"
occurrenceCount: "5"
pluginId: "90003"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "5"
wascId: "15"
---

# Sub Resource Integrity Attribute Missing (Plugin 90003)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/SubResourceIntegrityAttributeScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/SubResourceIntegrityAttributeScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90003/

### How it detects

Passive; sets evidence

## Remediation

Provide a valid integrity attribute to the tag.

### References
- https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity

## Issues

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6135e12afcefb35c.md|Issue fin-6135e12afcefb35c]]
#### Observations
- [[occurrences/occ-d098e0588dc82137.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-132cffbac3a947d4.md|Issue fin-132cffbac3a947d4]]
#### Observations
- [[occurrences/occ-64f8e629943970c6.md|attribute_script]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1d408ac781ad2565.md|Issue fin-1d408ac781ad2565]]
#### Observations
- [[occurrences/occ-6cdb0922f8fe27c2.md|attribute_script]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce4b33c404d4fa23.md|Issue fin-ce4b33c404d4fa23]]
#### Observations
- [[occurrences/occ-bd374412fc1b7e1a.md|script]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7a7e5da59bc3caec.md|Issue fin-7a7e5da59bc3caec]]
#### Observations
- [[occurrences/occ-ae86deedaca23a26.md|jquery.html]]

