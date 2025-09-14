---
aliases:
  - "SISTB-0024"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40024"
name: "SQL Injection - SQLite (Time Based)"
occurrenceCount: "0"
pluginId: "40024"
schemaVersion: "v1"
sourceTool: "zap"
---

# SQL Injection - SQLite (Time Based) (Plugin 40024)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionSqLiteTimingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionSqLiteTimingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40024/

### How it detects

Active; uses regex patterns; sets evidence; threshold: low; strength: low

_threshold: low; strength: low_

Signals:
- regex:no such function: randomblob
- regex:near \\\

### References
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

