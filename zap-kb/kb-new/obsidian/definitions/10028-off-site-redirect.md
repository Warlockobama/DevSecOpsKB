---
aliases:
  - "OSR-0028"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10028"
name: "Off-site Redirect"
occurrenceCount: "0"
pluginId: "10028"
schemaVersion: "v1"
sourceTool: "zap"
---

# Off-site Redirect (Plugin 10028)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledOpenRedirectScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledOpenRedirectScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10028/

### How it detects

Passive

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/601.html

