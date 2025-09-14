---
aliases:
  - "SSTIB-0036"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90036"
name: "Server Side Template Injection (Blind)"
occurrenceCount: "0"
pluginId: "90036"
schemaVersion: "v1"
sourceTool: "zap"
---

# Server Side Template Injection (Blind) (Plugin 90036)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SstiBlindScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SstiBlindScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90036/

### How it detects

Active; strength: high

_strength: high_

### References
- https://portswigger.net/blog/server-side-template-injection

