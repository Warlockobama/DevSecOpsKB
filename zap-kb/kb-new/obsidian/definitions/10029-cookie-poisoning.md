---
aliases:
  - "CP-0029"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10029"
name: "Cookie Poisoning"
occurrenceCount: "0"
pluginId: "10029"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cookie Poisoning (Plugin 10029)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledCookieScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledCookieScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10029/

### How it detects

Passive; checks headers: Set-Cookie

Signals:
- header:Set-Cookie

### References
- https://en.wikipedia.org/wiki/HTTP_cookie
- https://cwe.mitre.org/data/definitions/565.html

