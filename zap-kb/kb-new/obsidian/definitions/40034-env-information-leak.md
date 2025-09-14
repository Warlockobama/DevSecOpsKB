---
aliases:
  - "EIL-0034"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40034"
name: ".env Information Leak"
occurrenceCount: "0"
pluginId: "40034"
schemaVersion: "v1"
sourceTool: "zap"
---

# .env Information Leak (Plugin 40034)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/EnvFileScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/EnvFileScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40034/

### How it detects

Active; uses regex patterns

Signals:
- regex:^#\\s{0,10}\\w+
- regex:^\\w+=\\w+

### References
- https://www.google.com/search?q=db_password&#43;filetype%3Aenv
- https://mobile.twitter.com/svblxyz/status/1045013939904532482

