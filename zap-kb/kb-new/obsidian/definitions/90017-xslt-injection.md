---
aliases:
  - "XI-0017"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90017"
name: "XSLT Injection"
occurrenceCount: "0"
pluginId: "90017"
schemaVersion: "v1"
sourceTool: "zap"
---

# XSLT Injection (Plugin 90017)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/XsltInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/XsltInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90017/

### How it detects

Active; sets evidence; strength: low

_strength: low_

### References
- https://www.contextis.com/blog/xslt-server-side-injection-attacks

