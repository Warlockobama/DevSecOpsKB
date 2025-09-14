---
aliases:
  - "UCC-0030"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10030"
name: "User Controllable Charset"
occurrenceCount: "0"
pluginId: "10030"
schemaVersion: "v1"
sourceTool: "zap"
---

# User Controllable Charset (Plugin 10030)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledCharsetScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledCharsetScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10030/

### How it detects

Passive; checks headers: Content-Type

Signals:
- header:Content-Type

