---
aliases:
  - "UCHEA-0031"
cweId: "20"
cweUri: "https://cwe.mitre.org/data/definitions/20.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10031"
name: "User Controllable HTML Element Attribute (Potential XSS)"
occurrenceCount: "6"
pluginId: "10031"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "6"
wascId: "20"
---

# User Controllable HTML Element Attribute (Potential XSS) (Plugin 10031)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledHTMLAttributesScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledHTMLAttributesScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10031/

### How it detects

Passive; checks headers: Content-Type

Signals:
- header:Content-Type

## Remediation

Validate all input and sanitize output it before writing to any HTML attributes.

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

## Issues

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4219194ae4c318e0.md|Issue fin-4219194ae4c318e0]]
#### Observations
- [[occurrences/occ-faa9e96732ed0712.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-955d0e90bf3dcfa3.md|Issue fin-955d0e90bf3dcfa3]]
#### Observations
- [[occurrences/occ-00c8baa573b785d4.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aee1532422b83749.md|Issue fin-aee1532422b83749]]
#### Observations
- [[occurrences/occ-5dbe612d56127bf1.md|meta[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b046d4058d56ff60.md|Issue fin-b046d4058d56ff60]]
#### Observations
- [[occurrences/occ-453f503a3ff35bd4.md|application_x-shockwave-flash[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-60d69f10240b187c.md|Issue fin-60d69f10240b187c]]
#### Observations
- [[occurrences/occ-d1166eb084430998.md|object_raw[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-541791d57d76f3d6.md|Issue fin-541791d57d76f3d6]]
#### Observations
- [[occurrences/occ-9cb981b1d5cb8f08.md|script[q]]]

