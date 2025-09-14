---
aliases:
  - "HPO-0026"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10026"
name: "HTTP Parameter Override"
occurrenceCount: "0"
pluginId: "10026"
schemaVersion: "v1"
sourceTool: "zap"
---

# HTTP Parameter Override (Plugin 10026)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/ServletParameterPollutionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/ServletParameterPollutionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10026/

### How it detects

Passive; sets evidence; threshold: low

_threshold: low_

