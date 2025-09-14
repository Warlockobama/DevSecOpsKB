---
aliases:
  - "ER-0019"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-20019"
name: "External Redirect"
occurrenceCount: "0"
pluginId: "20019"
schemaVersion: "v1"
sourceTool: "zap"
---

# External Redirect (Plugin 20019)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ExternalRedirectScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ExternalRedirectScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/20019/

### How it detects

Active; checks headers: Scheme-Https, Scheme-Http, Http; uses regex patterns; sets evidence

Signals:
- header:Scheme-Https
- header:Scheme-Http
- header:Http
- regex:(?i)location(?:\\.href)?\\s*=\\s*['\
- regex:(?i)location\\.(?:replace|reload|assign)\\s*\\(\\s*['\

