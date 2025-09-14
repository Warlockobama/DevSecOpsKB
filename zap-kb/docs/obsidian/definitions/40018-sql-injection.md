---
aliases:
  - "SI-0018"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-40018"
name: "SQL Injection"
occurrenceCount: "0"
pluginId: "40018"
schemaVersion: "v1"
sourceTool: "zap"
---

# SQL Injection (Plugin 40018)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40018/

### How it detects

Active; checks headers: Location; sets evidence; threshold: medium; strength: low

_threshold: medium; strength: low_

Signals:
- header:Location

