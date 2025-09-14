---
aliases:
  - "NIMTB-0039"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90039"
name: "NoSQL Injection - MongoDB (Time Based)"
occurrenceCount: "0"
pluginId: "90039"
schemaVersion: "v1"
sourceTool: "zap"
---

# NoSQL Injection - MongoDB (Time Based) (Plugin 90039)

## Detection logic

- Logic: active
- Add-on: ascanrulesAlpha
- Source path: `zap-extensions/addOns/ascanrulesAlpha/src/main/java/org/zaproxy/zap/extension/ascanrulesAlpha/MongoDbInjectionTimingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesAlpha/src/main/java/org/zaproxy/zap/extension/ascanrulesAlpha/MongoDbInjectionTimingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90039/

### How it detects

Active

### References
- https://arxiv.org/pdf/1506.04082.pdf
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.html

