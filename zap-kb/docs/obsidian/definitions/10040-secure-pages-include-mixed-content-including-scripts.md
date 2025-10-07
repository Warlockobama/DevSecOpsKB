---
aliases:
  - "SPIMC-0040"
cweId: "311"
cweUri: "https://cwe.mitre.org/data/definitions/311.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10040"
name: "Secure Pages Include Mixed Content (Including Scripts)"
occurrenceCount: "5"
pluginId: "10040"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "5"
wascId: "4"
---

# Secure Pages Include Mixed Content (Including Scripts) (Plugin 10040)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/MixedContentScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/MixedContentScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10040/

### How it detects

Passive; sets evidence

## Remediation

A page that is available over SSL/TLS must be comprised completely of content which is transmitted over SSL/TLS.
The page must not contain any content that is transmitted over unencrypted HTTP.
This includes content from third party sites.

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

## Issues

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-72db31626be3858f.md|Issue fin-72db31626be3858f]]
#### Observations
- [[occurrences/occ-a87732175431b7d8.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2d243c5065dcdb2d.md|Issue fin-2d243c5065dcdb2d]]
#### Observations
- [[occurrences/occ-f5721c8cbac017a3.md|attribute_script]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2e68fbff9a9ae698.md|Issue fin-2e68fbff9a9ae698]]
#### Observations
- [[occurrences/occ-c55822a93cbfd28c.md|mixedcontent]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-517277af37e97c2a.md|Issue fin-517277af37e97c2a]]
#### Observations
- [[occurrences/occ-cb88ee46d5a3b8c1.md|mixedcontent/index.html]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c6b9032a8e2c378c.md|Issue fin-c6b9032a8e2c378c]]
#### Observations
- [[occurrences/occ-caa8418858eeabc6.md|attribute_script]]

