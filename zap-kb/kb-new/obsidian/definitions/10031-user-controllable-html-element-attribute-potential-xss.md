---
aliases:
  - "UCHEA-0031"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10031"
name: "User Controllable HTML Element Attribute (Potential XSS)"
occurrenceCount: "0"
pluginId: "10031"
schemaVersion: "v1"
sourceTool: "zap"
---

# User Controllable HTML Element Attribute (Potential XSS) (Plugin 10031)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledHTMLAttributesScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UserControlledHTMLAttributesScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10031/

### How it detects

Passive; checks headers: Content-Type

Signals:
- header:Content-Type

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

