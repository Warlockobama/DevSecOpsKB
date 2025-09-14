---
aliases:
  - "UCJEX-0043"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10043"
name: "User Controllable JavaScript Event (XSS)"
occurrenceCount: "0"
pluginId: "10043"
schemaVersion: "v1"
sourceTool: "zap"
---

# User Controllable JavaScript Event (XSS) (Plugin 10043)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledJavascriptEventScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledJavascriptEventScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10043/

### How it detects

Passive; checks headers: Content-Type

Signals:
- header:Content-Type

