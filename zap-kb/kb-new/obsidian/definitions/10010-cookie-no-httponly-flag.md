---
aliases:
  - "CNHF-0010"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10010"
name: "Cookie No HttpOnly Flag"
occurrenceCount: "0"
pluginId: "10010"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cookie No HttpOnly Flag (Plugin 10010)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieHttpOnlyScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieHttpOnlyScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10010/

### How it detects

Passive; checks headers: Set-Cookie; sets evidence

Signals:
- header:Set-Cookie

### References
- https://owasp.org/www-community/HttpOnly

