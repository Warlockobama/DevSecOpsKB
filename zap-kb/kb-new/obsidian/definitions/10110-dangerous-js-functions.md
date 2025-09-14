---
aliases:
  - "DJF-0110"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10110"
name: "Dangerous JS Functions"
occurrenceCount: "0"
pluginId: "10110"
schemaVersion: "v1"
sourceTool: "zap"
---

# Dangerous JS Functions (Plugin 10110)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/JsFunctionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/JsFunctionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10110/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:\\b\\$?

### References
- https://angular.io/guide/security

