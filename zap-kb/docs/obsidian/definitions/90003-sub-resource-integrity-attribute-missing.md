---
aliases:
  - "SRIA-0003"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90003"
name: "Sub Resource Integrity Attribute Missing"
occurrenceCount: "0"
pluginId: "90003"
schemaVersion: "v1"
sourceTool: "zap"
---

# Sub Resource Integrity Attribute Missing (Plugin 90003)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/SubResourceIntegrityAttributeScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/SubResourceIntegrityAttributeScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90003/

### How it detects

Passive; sets evidence

