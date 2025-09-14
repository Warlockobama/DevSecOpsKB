---
aliases:
  - "ARI-0111"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10111"
name: "Authentication Request Identified"
occurrenceCount: "0"
pluginId: "10111"
schemaVersion: "v1"
sourceTool: "zap"
---

# Authentication Request Identified (Plugin 10111)

## Detection logic

- Logic: unknown
- Add-on: authhelper
- Source path: `zap-extensions/addOns/authhelper/src/main/java/org/zaproxy/addon/authhelper/AuthenticationDetectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/authhelper/src/main/java/org/zaproxy/addon/authhelper/AuthenticationDetectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10111/

### How it detects

Unknown; checks headers: Referer; sets evidence

Signals:
- header:Referer

