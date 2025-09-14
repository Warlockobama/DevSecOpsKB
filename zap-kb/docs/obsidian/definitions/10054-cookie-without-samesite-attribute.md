---
aliases:
  - "CWSA-0054"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10054"
name: "Cookie without SameSite Attribute"
occurrenceCount: "0"
pluginId: "10054"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cookie without SameSite Attribute (Plugin 10054)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieSameSiteScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieSameSiteScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10054/

### How it detects

Passive; checks headers: Set-Cookie; sets evidence; threshold: high

_threshold: high_

Signals:
- header:Set-Cookie

