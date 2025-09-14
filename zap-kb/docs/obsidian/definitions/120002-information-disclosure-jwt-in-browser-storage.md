---
aliases:
  - "IDJBS-0002"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-120002"
name: "Information Disclosure - JWT in Browser Storage"
occurrenceCount: "0"
pluginId: "120002"
schemaVersion: "v1"
sourceTool: "zap"
---

# Information Disclosure - JWT in Browser Storage (Plugin 120002)

## Detection logic

- Logic: passive
- Add-on: client
- Source path: `zap-extensions/addOns/client/src/main/java/org/zaproxy/addon/client/pscan/JwtInStorageScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/client/src/main/java/org/zaproxy/addon/client/pscan/JwtInStorageScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/120002/

### How it detects

Passive

