---
aliases:
  - "IHM-0028"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90028"
name: "Insecure HTTP Method"
occurrenceCount: "0"
pluginId: "90028"
schemaVersion: "v1"
sourceTool: "zap"
---

# Insecure HTTP Method (Plugin 90028)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/InsecureHttpMethodScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/InsecureHttpMethodScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90028/

### How it detects

Active; uses regex patterns; sets evidence; threshold: low; strength: medium

_threshold: low; strength: medium_

Signals:
- regex:<title.*{1,10}Google.{1,25}/title>

### References
- https://cwe.mitre.org/data/definitions/205.html

