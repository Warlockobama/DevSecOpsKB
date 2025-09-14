---
aliases:
  - "CDJSF-0017"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10017"
name: "Cross-Domain JavaScript Source File Inclusion"
occurrenceCount: "0"
pluginId: "10017"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cross-Domain JavaScript Source File Inclusion (Plugin 10017)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CrossDomainScriptInclusionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CrossDomainScriptInclusionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10017/

### How it detects

Passive; sets evidence; threshold: low

_threshold: low_

