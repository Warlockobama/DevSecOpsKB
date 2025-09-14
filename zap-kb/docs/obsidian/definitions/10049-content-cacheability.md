---
aliases:
  - "CC-0049"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10049"
name: "Content Cacheability"
occurrenceCount: "0"
pluginId: "10049"
schemaVersion: "v1"
sourceTool: "zap"
---

# Content Cacheability (Plugin 10049)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/CacheableScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/CacheableScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10049/

### How it detects

Passive; checks headers: Pragma, Cache-Control, Authorization; sets evidence

Signals:
- header:Pragma
- header:Cache-Control
- header:Authorization

