---
aliases:
  - "PD-0062"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10062"
name: "PII Disclosure"
occurrenceCount: "0"
pluginId: "10062"
schemaVersion: "v1"
sourceTool: "zap"
---

# PII Disclosure (Plugin 10062)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/PiiScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/PiiScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10062/

### How it detects

Passive; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- regex:(?:\\.pdf)\\z

