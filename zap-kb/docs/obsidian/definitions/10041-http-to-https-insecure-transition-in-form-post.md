---
aliases:
  - "HHITF-0041"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10041"
name: "HTTP to HTTPS Insecure Transition in Form Post"
occurrenceCount: "0"
pluginId: "10041"
schemaVersion: "v1"
sourceTool: "zap"
---

# HTTP to HTTPS Insecure Transition in Form Post (Plugin 10041)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InsecureFormLoadScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InsecureFormLoadScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10041/

### How it detects

Passive; checks headers: Https, Content-Type; sets evidence

Signals:
- header:Https
- header:Content-Type

