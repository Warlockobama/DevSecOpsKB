---
aliases:
  - "EEEBL-0044"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40044"
name: "Exponential Entity Expansion (Billion Laughs Attack)"
occurrenceCount: "0"
pluginId: "40044"
schemaVersion: "v1"
sourceTool: "zap"
---

# Exponential Entity Expansion (Billion Laughs Attack) (Plugin 40044)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ExponentialEntityExpansionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ExponentialEntityExpansionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40044/

### How it detects

Active

### References
- https://en.wikipedia.org/wiki/Billion_laughs_attack
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing
- https://cwe.mitre.org/data/definitions/776.html

