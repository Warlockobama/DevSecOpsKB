---
aliases:
  - "CWSF-0011"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10011"
name: "Cookie Without Secure Flag"
occurrenceCount: "0"
pluginId: "10011"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cookie Without Secure Flag (Plugin 10011)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieSecureFlagScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieSecureFlagScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10011/

### How it detects

Passive; checks headers: Set-Cookie; sets evidence

Signals:
- header:Set-Cookie

