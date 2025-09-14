---
aliases:
  - "NIM-0033"
generatedAt: "2025-09-04T00:31:04Z"
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

