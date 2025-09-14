---
aliases:
  - "XEEA-0023"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90023"
name: "XML External Entity Attack"
occurrenceCount: "0"
pluginId: "90023"
schemaVersion: "v1"
sourceTool: "zap"
---

# XML External Entity Attack (Plugin 90023)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/XxeScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/XxeScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90023/

### How it detects

Active; uses regex patterns; sets evidence; strength: low

_strength: low_

Signals:
- regex:root:.:0:0
- regex:\\[drivers\\]

