---
aliases:
  - "GPO-0024"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90024"
name: "Generic Padding Oracle"
occurrenceCount: "0"
pluginId: "90024"
schemaVersion: "v1"
sourceTool: "zap"
---

# Generic Padding Oracle (Plugin 90024)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/PaddingOracleScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/PaddingOracleScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90024/

### How it detects

Active; uses regex patterns; sets evidence

Signals:
- regex:^([a-fA-F0-9]{2})+$
- regex:^[a-zA-Z0-9_-]+[012]$

