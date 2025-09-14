---
aliases:
  - "AED-0022"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90022"
name: "Application Error Disclosure"
occurrenceCount: "0"
pluginId: "90022"
schemaVersion: "v1"
sourceTool: "zap"
---

# Application Error Disclosure (Plugin 90022)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ApplicationErrorScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ApplicationErrorScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90022/

### How it detects

Passive; sets evidence; threshold: high

_threshold: high_

