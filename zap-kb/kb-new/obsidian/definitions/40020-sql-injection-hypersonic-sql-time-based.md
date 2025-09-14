---
aliases:
  - "SIHST-0020"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40020"
name: "SQL Injection - Hypersonic SQL (Time Based)"
occurrenceCount: "0"
pluginId: "40020"
schemaVersion: "v1"
sourceTool: "zap"
---

# SQL Injection - Hypersonic SQL (Time Based) (Plugin 40020)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionHypersonicTimingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionHypersonicTimingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40020/

### How it detects

Active; strength: low

_strength: low_

### References
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

