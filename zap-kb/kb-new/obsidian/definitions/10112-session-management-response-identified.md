---
aliases:
  - "SMRI-0112"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10112"
name: "Session Management Response Identified"
occurrenceCount: "0"
pluginId: "10112"
schemaVersion: "v1"
sourceTool: "zap"
---

# Session Management Response Identified (Plugin 10112)

## Detection logic

- Logic: passive
- Add-on: authhelper
- Source path: `zap-extensions/addOns/authhelper/src/main/java/org/zaproxy/addon/authhelper/SessionDetectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/authhelper/src/main/java/org/zaproxy/addon/authhelper/SessionDetectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10112/

### How it detects

Passive; checks headers: Authorization; sets evidence

Signals:
- header:Authorization

### References
- https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id

