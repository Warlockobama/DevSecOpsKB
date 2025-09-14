---
aliases:
  - "XBSIL-0039"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10039"
name: "X-Backend-Server Header Information Leak"
occurrenceCount: "0"
pluginId: "10039"
schemaVersion: "v1"
sourceTool: "zap"
---

# X-Backend-Server Header Information Leak (Plugin 10039)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XBackendServerInformationLeakScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XBackendServerInformationLeakScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10039/

### How it detects

Passive; sets evidence

