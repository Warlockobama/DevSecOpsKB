---
aliases:
  - "HOS-0106"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10106"
name: "HTTP Only Site"
occurrenceCount: "0"
pluginId: "10106"
schemaVersion: "v1"
sourceTool: "zap"
---

# HTTP Only Site (Plugin 10106)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/HttpOnlySiteScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/HttpOnlySiteScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10106/

### How it detects

Active; checks headers: Scheme-Http, Scheme-Https

Signals:
- header:Scheme-Http
- header:Scheme-Https

