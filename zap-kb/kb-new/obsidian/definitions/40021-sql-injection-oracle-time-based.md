---
aliases:
  - "SIOTB-0021"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40021"
name: "SQL Injection - Oracle (Time Based)"
occurrenceCount: "0"
pluginId: "40021"
schemaVersion: "v1"
sourceTool: "zap"
---

# SQL Injection - Oracle (Time Based) (Plugin 40021)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionOracleTimingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionOracleTimingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40021/

### How it detects

Active; strength: low

_strength: low_

### References
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

