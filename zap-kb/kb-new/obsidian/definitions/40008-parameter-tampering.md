---
aliases:
  - "PT-0008"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40008"
name: "Parameter Tampering"
occurrenceCount: "0"
pluginId: "40008"
schemaVersion: "v1"
sourceTool: "zap"
---

# Parameter Tampering (Plugin 40008)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ParameterTamperScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ParameterTamperScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40008/

### How it detects

Active; uses regex patterns; sets evidence

Signals:
- regex:javax\\.servlet\\.\\S+
- regex:invoke.+exception|exception.+invoke

