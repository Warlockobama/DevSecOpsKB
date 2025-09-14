---
aliases:
  - "BRPSI-0044"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10044"
name: "Big Redirect Detected (Potential Sensitive Information Leak)"
occurrenceCount: "0"
pluginId: "10044"
schemaVersion: "v1"
sourceTool: "zap"
---

# Big Redirect Detected (Potential Sensitive Information Leak) (Plugin 10044)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/BigRedirectsScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/BigRedirectsScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10044/

### How it detects

Passive; checks headers: Location; uses regex patterns

Signals:
- header:Location
- regex:href

