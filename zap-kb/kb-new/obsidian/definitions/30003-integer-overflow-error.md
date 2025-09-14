---
aliases:
  - "IOE-0003"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-30003"
name: "Integer Overflow Error"
occurrenceCount: "0"
pluginId: "30003"
schemaVersion: "v1"
sourceTool: "zap"
---

# Integer Overflow Error (Plugin 30003)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/IntegerOverflowScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/IntegerOverflowScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/30003/

### How it detects

Active; sets evidence

### References
- https://en.wikipedia.org/wiki/Integer_overflow
- https://cwe.mitre.org/data/definitions/190.html

