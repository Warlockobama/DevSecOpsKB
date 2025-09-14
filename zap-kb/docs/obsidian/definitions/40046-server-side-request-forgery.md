---
aliases:
  - "SSRF-0046"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-40046"
name: "Server Side Request Forgery"
occurrenceCount: "0"
pluginId: "40046"
schemaVersion: "v1"
sourceTool: "zap"
---

# Server Side Request Forgery (Plugin 40046)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SsrfScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SsrfScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40046/

### How it detects

Active; checks headers: Scheme-Http, Scheme-Https; sets evidence

Signals:
- header:Scheme-Http
- header:Scheme-Https

