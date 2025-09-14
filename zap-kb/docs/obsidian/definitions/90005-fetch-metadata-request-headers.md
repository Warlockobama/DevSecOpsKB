---
aliases:
  - "FMRH-0005"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90005"
name: "Fetch Metadata Request Headers"
occurrenceCount: "0"
pluginId: "90005"
schemaVersion: "v1"
sourceTool: "zap"
---

# Fetch Metadata Request Headers (Plugin 90005)

## Detection logic

- Logic: passive
- Add-on: pscanrulesAlpha
- Source path: `zap-extensions/addOns/pscanrulesAlpha/src/main/java/org/zaproxy/zap/extension/pscanrulesAlpha/FetchMetadataRequestHeadersScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesAlpha/src/main/java/org/zaproxy/zap/extension/pscanrulesAlpha/FetchMetadataRequestHeadersScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90005/

### How it detects

Passive; sets evidence

