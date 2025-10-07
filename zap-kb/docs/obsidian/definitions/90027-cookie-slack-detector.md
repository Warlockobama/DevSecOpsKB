---
aliases:
  - "CSD-0027"
cweId: "205"
cweUri: "https://cwe.mitre.org/data/definitions/205.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-90027"
name: "Cookie Slack Detector"
occurrenceCount: "2"
pluginId: "90027"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "2"
wascId: "45"
---

# Cookie Slack Detector (Plugin 90027)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SlackerCookieScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SlackerCookieScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90027/

### How it detects

Active

### References
- https://cwe.mitre.org/data/definitions/205.html

## Issues

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e2e2d735b6039b60.md|Issue fin-e2e2d735b6039b60]]
#### Observations
- [[occurrences/occ-839222512be1da66.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f1f34bece5c9fb04.md|Issue fin-f1f34bece5c9fb04]]
#### Observations
- [[occurrences/occ-5f569d94de632077.md|leakedinresource]]

