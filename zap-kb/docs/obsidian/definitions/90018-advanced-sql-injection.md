---
aliases:
  - "ASI-0018"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90018"
name: "Advanced SQL Injection"
occurrenceCount: "0"
pluginId: "90018"
schemaVersion: "v1"
sourceTool: "zap"
---

# Advanced SQL Injection (Plugin 90018)

## Detection logic

- Logic: unknown
- Add-on: sqliplugin
- Source path: `zap-extensions/addOns/sqliplugin/src/main/java/org/zaproxy/zap/extension/sqliplugin/SQLInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/sqliplugin/src/main/java/org/zaproxy/zap/extension/sqliplugin/SQLInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90018/

### How it detects

Unknown; checks headers: Connection, -Keep-Alive, -Close; uses regex patterns

Signals:
- header:Connection
- header:-Keep-Alive
- header:-Close
- regex:SQL (warning|error|syntax)
- regex:\\[RANDNUM(?:\\d+)?\\]

