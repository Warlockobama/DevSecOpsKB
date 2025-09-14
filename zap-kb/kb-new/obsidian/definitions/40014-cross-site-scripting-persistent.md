---
aliases:
  - "CSSP-0014"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40014"
name: "Cross Site Scripting (Persistent)"
occurrenceCount: "0"
pluginId: "40014"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cross Site Scripting (Persistent) (Plugin 40014)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/PersistentXssScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/PersistentXssScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40014/

### How it detects

Active; sets evidence; threshold: high

_threshold: high_

### References
- https://owasp.org/www-community/attacks/xss/
- https://cwe.mitre.org/data/definitions/79.html

