---
aliases:
  - "CSSDB-0026"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40026"
name: "Cross Site Scripting (DOM Based)"
occurrenceCount: "0"
pluginId: "40026"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cross Site Scripting (DOM Based) (Plugin 40026)

## Detection logic

- Logic: active
- Add-on: domxss
- Source path: `zap-extensions/addOns/domxss/src/main/java/org/zaproxy/zap/extension/domxss/DomXssScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/domxss/src/main/java/org/zaproxy/zap/extension/domxss/DomXssScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40026/

### How it detects

Active; threshold: low; strength: low

_threshold: low; strength: low_

### References
- https://owasp.org/www-community/attacks/xss/
- https://cwe.mitre.org/data/definitions/79.html

