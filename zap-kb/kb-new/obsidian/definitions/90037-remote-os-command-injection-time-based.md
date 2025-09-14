---
aliases:
  - "ROCIT-0037"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90037"
name: "Remote OS Command Injection (Time Based)"
occurrenceCount: "0"
pluginId: "90037"
schemaVersion: "v1"
sourceTool: "zap"
---

# Remote OS Command Injection (Time Based) (Plugin 90037)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CommandInjectionTimingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CommandInjectionTimingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90037/

### How it detects

Active

### References
- https://cwe.mitre.org/data/definitions/78.html
- https://owasp.org/www-community/attacks/Command_Injection

