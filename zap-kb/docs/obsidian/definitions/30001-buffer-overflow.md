---
aliases:
  - "BO-0001"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-30001"
name: "Buffer Overflow"
occurrenceCount: "0"
pluginId: "30001"
schemaVersion: "v1"
sourceTool: "zap"
---

# Buffer Overflow (Plugin 30001)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/BufferOverflowScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/BufferOverflowScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/30001/

### How it detects

Active; sets evidence

