---
aliases:
  - "SSI-0009"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-40009"
name: "Server Side Include"
occurrenceCount: "0"
pluginId: "40009"
schemaVersion: "v1"
sourceTool: "zap"
---

# Server Side Include (Plugin 40009)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ServerSideIncludeScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ServerSideIncludeScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40009/

### How it detects

Active; uses regex patterns; sets evidence

Signals:
- regex:\\broot\\b.*\\busr\\b
- regex:\\bprogram files\\b.*\\b(WINDOWS|WINNT)\\b

