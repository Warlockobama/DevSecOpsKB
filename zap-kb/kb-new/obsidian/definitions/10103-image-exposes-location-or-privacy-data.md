---
aliases:
  - "IELOP-0103"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10103"
name: "Image Exposes Location or Privacy Data"
occurrenceCount: "0"
pluginId: "10103"
schemaVersion: "v1"
sourceTool: "zap"
---

# Image Exposes Location or Privacy Data (Plugin 10103)

## Detection logic

- Logic: passive
- Add-on: imagelocationscanner
- Source path: `zap-extensions/addOns/imagelocationscanner/src/main/java/org/zaproxy/zap/extension/imagelocationscanner/ImageLocationScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/imagelocationscanner/src/main/java/org/zaproxy/zap/extension/imagelocationscanner/ImageLocationScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10103/

### How it detects

Passive; checks headers: Content-Type; sets evidence

Signals:
- header:Content-Type

### References
- https://www.veggiespam.com/ils/

