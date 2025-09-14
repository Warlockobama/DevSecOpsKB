---
aliases:
  - "RCESS-0048"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10048"
name: "Remote Code Execution - Shell Shock"
occurrenceCount: "0"
pluginId: "10048"
schemaVersion: "v1"
sourceTool: "zap"
---

# Remote Code Execution - Shell Shock (Plugin 10048)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ShellShockScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ShellShockScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10048/

### How it detects

Active; sets evidence

