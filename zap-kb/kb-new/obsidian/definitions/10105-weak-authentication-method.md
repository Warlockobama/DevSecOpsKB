---
aliases:
  - "WAM-0105"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10105"
name: "Weak Authentication Method"
occurrenceCount: "0"
pluginId: "10105"
schemaVersion: "v1"
sourceTool: "zap"
---

# Weak Authentication Method (Plugin 10105)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InsecureAuthenticationScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InsecureAuthenticationScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10105/

### How it detects

Passive; checks headers: Authorization, Www-Authenticate; uses regex patterns; sets evidence

Signals:
- header:Authorization
- header:Www-Authenticate
- regex:.*username=\

