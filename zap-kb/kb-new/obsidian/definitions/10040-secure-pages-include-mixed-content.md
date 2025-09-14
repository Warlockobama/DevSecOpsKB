---
aliases:
  - "SPIMC-0040"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10040"
name: "Secure Pages Include Mixed Content"
occurrenceCount: "0"
pluginId: "10040"
schemaVersion: "v1"
sourceTool: "zap"
---

# Secure Pages Include Mixed Content (Plugin 10040)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/MixedContentScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/MixedContentScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10040/

### How it detects

Passive; sets evidence

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

