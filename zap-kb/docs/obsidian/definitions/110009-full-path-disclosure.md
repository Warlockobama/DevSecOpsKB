---
aliases:
  - "FPD-0009"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-110009"
name: "Full Path Disclosure"
occurrenceCount: "0"
pluginId: "110009"
schemaVersion: "v1"
sourceTool: "zap"
---

# Full Path Disclosure (Plugin 110009)

## Detection logic

- Logic: passive
- Add-on: pscanrulesAlpha
- Source path: `zap-extensions/addOns/pscanrulesAlpha/src/main/java/org/zaproxy/zap/extension/pscanrulesAlpha/FullPathDisclosureScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesAlpha/src/main/java/org/zaproxy/zap/extension/pscanrulesAlpha/FullPathDisclosureScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/110009/

### How it detects

Passive; sets evidence

