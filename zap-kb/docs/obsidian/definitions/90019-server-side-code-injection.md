---
aliases:
  - "SSCI-0019"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90019"
name: "Server Side Code Injection"
occurrenceCount: "0"
pluginId: "90019"
schemaVersion: "v1"
sourceTool: "zap"
---

# Server Side Code Injection (Plugin 90019)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CodeInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CodeInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90019/

### How it detects

Active; sets evidence

