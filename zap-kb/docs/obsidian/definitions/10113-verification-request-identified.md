---
aliases:
  - "VRI-0113"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10113"
name: "Verification Request Identified"
occurrenceCount: "0"
pluginId: "10113"
schemaVersion: "v1"
sourceTool: "zap"
---

# Verification Request Identified (Plugin 10113)

## Detection logic

- Logic: unknown
- Add-on: authhelper
- Source path: `zap-extensions/addOns/authhelper/src/main/java/org/zaproxy/addon/authhelper/VerificationDetectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/authhelper/src/main/java/org/zaproxy/addon/authhelper/VerificationDetectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10113/

### How it detects

Unknown; checks headers: Authorization; sets evidence

Signals:
- header:Authorization

