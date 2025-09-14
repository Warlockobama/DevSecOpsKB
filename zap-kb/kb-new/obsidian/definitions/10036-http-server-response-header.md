---
aliases:
  - "HSR-0036"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10036"
name: "HTTP Server Response Header"
occurrenceCount: "0"
pluginId: "10036"
schemaVersion: "v1"
sourceTool: "zap"
---

# HTTP Server Response Header (Plugin 10036)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ServerHeaderInfoLeakScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ServerHeaderInfoLeakScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10036/

### How it detects

Passive; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- regex:.*\\d.*

