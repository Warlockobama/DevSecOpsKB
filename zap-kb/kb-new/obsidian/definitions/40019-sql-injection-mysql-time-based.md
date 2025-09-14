---
aliases:
  - "SIMTB-0019"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40019"
name: "SQL Injection - MySQL (Time Based)"
occurrenceCount: "0"
pluginId: "40019"
schemaVersion: "v1"
sourceTool: "zap"
---

# SQL Injection - MySQL (Time Based) (Plugin 40019)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionMySqlTimingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionMySqlTimingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40019/

### How it detects

Active; strength: low

_strength: low_

### References
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

