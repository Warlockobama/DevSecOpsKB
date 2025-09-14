---
aliases:
  - "EIL-0028"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40028"
name: "ELMAH Information Leak"
occurrenceCount: "0"
pluginId: "40028"
schemaVersion: "v1"
sourceTool: "zap"
---

# ELMAH Information Leak (Plugin 40028)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ElmahScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ElmahScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40028/

### How it detects

Active

### References
- https://www.troyhunt.com/aspnet-session-hijacking-with-google/
- https://www.nuget.org/packages/elmah
- https://elmah.github.io/

