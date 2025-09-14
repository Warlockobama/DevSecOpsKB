---
aliases:
  - "CM-0011"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90011"
name: "Charset Mismatch"
occurrenceCount: "0"
pluginId: "90011"
schemaVersion: "v1"
sourceTool: "zap"
---

# Charset Mismatch (Plugin 90011)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CharsetMismatchScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CharsetMismatchScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90011/

### How it detects

Passive; checks headers: Content-Type; threshold: low

_threshold: low_

Signals:
- header:Content-Type

### References
- https://code.google.com/p/browsersec/wiki/Part2#Character_set_handling_and_detection

