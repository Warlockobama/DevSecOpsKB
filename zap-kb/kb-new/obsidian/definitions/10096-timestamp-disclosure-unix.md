---
aliases:
  - "TDU-0096"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10096"
name: "Timestamp Disclosure - Unix"
occurrenceCount: "0"
pluginId: "10096"
schemaVersion: "v1"
sourceTool: "zap"
---

# Timestamp Disclosure - Unix (Plugin 10096)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/TimestampDisclosureScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/TimestampDisclosureScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10096/

### How it detects

Passive; checks headers: -Keep-Alive, Cache-Control; uses regex patterns; sets evidence; threshold: high

_threshold: high_

Signals:
- header:-Keep-Alive
- header:Cache-Control
- regex:\\b(?:1\\d|2[0-2])\\d{8}\\b(?!%)

### References
- https://cwe.mitre.org/data/definitions/200.html

