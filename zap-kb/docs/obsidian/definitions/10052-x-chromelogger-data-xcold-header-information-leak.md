---
aliases:
  - "XCDXI-0052"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10052"
name: "X-ChromeLogger-Data (XCOLD) Header Information Leak"
occurrenceCount: "0"
pluginId: "10052"
schemaVersion: "v1"
sourceTool: "zap"
---

# X-ChromeLogger-Data (XCOLD) Header Information Leak (Plugin 10052)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XChromeLoggerDataInfoLeakScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XChromeLoggerDataInfoLeakScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10052/

### How it detects

Passive; sets evidence

