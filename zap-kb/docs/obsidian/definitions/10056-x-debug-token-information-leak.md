---
aliases:
  - "XDTIL-0056"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10056"
name: "X-Debug-Token Information Leak"
occurrenceCount: "0"
pluginId: "10056"
schemaVersion: "v1"
sourceTool: "zap"
---

# X-Debug-Token Information Leak (Plugin 10056)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XDebugTokenScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XDebugTokenScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10056/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:^

