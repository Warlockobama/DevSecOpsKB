---
aliases:
  - "HHITF-0042"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10042"
name: "HTTPS to HTTP Insecure Transition in Form Post"
occurrenceCount: "0"
pluginId: "10042"
schemaVersion: "v1"
sourceTool: "zap"
---

# HTTPS to HTTP Insecure Transition in Form Post (Plugin 10042)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InsecureFormPostScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InsecureFormPostScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10042/

### How it detects

Passive; checks headers: Content-Type; sets evidence

Signals:
- header:Content-Type

