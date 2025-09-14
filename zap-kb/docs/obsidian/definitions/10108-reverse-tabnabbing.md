---
aliases:
  - "RT-0108"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10108"
name: "Reverse Tabnabbing"
occurrenceCount: "0"
pluginId: "10108"
schemaVersion: "v1"
sourceTool: "zap"
---

# Reverse Tabnabbing (Plugin 10108)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/LinkTargetScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/LinkTargetScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10108/

### How it detects

Passive; sets evidence; threshold: low

_threshold: low_

