---
aliases:
  - "SIPTB-0022"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40022"
name: "SQL Injection - PostgreSQL (Time Based)"
occurrenceCount: "0"
pluginId: "40022"
schemaVersion: "v1"
sourceTool: "zap"
---

# SQL Injection - PostgreSQL (Time Based) (Plugin 40022)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionPostgreSqlTimingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionPostgreSqlTimingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40022/

### How it detects

Active; strength: low

_strength: low_

### References
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

