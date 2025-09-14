---
aliases:
  - "XI-0021"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90021"
name: "XPath Injection"
occurrenceCount: "0"
pluginId: "90021"
schemaVersion: "v1"
sourceTool: "zap"
---

# XPath Injection (Plugin 90021)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/XpathInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/XpathInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90021/

### How it detects

Active; sets evidence

### References
- https://owasp.org/www-community/attacks/XPATH_Injection
- https://owasp.org/www-community/attacks/Blind_XPath_Injection
- https://cwe.mitre.org/data/definitions/643.html

