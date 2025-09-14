---
aliases:
  - "ELI-0025"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90025"
name: "Expression Language Injection"
occurrenceCount: "0"
pluginId: "90025"
schemaVersion: "v1"
sourceTool: "zap"
---

# Expression Language Injection (Plugin 90025)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ExpressionLanguageInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ExpressionLanguageInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90025/

### How it detects

Active; sets evidence

### References
- https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection
- https://cwe.mitre.org/data/definitions/917.html

