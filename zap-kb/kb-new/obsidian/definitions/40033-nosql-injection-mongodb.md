---
aliases:
  - "NIM-0033"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40033"
name: "NoSQL Injection - MongoDB"
occurrenceCount: "0"
pluginId: "40033"
schemaVersion: "v1"
sourceTool: "zap"
---

# NoSQL Injection - MongoDB (Plugin 40033)

## Detection logic

- Logic: active
- Add-on: ascanrulesAlpha
- Source path: `zap-extensions/addOns/ascanrulesAlpha/src/main/java/org/zaproxy/zap/extension/ascanrulesAlpha/MongoDbInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesAlpha/src/main/java/org/zaproxy/zap/extension/ascanrulesAlpha/MongoDbInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40033/

### How it detects

Active; uses regex patterns

Signals:
- regex:RuntimeException: SyntaxError: unterminated string literal
- regex:MongoResultException

### References
- https://arxiv.org/pdf/1506.04082.pdf
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.html

