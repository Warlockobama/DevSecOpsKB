---
aliases:
  - "ROCI-0020"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90020"
name: "Remote OS Command Injection"
occurrenceCount: "0"
pluginId: "90020"
schemaVersion: "v1"
sourceTool: "zap"
---

# Remote OS Command Injection (Plugin 90020)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CommandInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CommandInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90020/

### How it detects

Active; uses regex patterns; sets evidence

Signals:
- regex:root:.:0:0
- regex:\\[fonts\\]

### References
- https://cwe.mitre.org/data/definitions/78.html
- https://owasp.org/www-community/attacks/Command_Injection

