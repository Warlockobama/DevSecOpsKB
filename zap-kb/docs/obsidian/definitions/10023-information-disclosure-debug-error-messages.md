---
aliases:
  - "IDDEM-0023"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10023"
name: "Information Disclosure - Debug Error Messages"
occurrenceCount: "0"
pluginId: "10023"
schemaVersion: "v1"
sourceTool: "zap"
---

# Information Disclosure - Debug Error Messages (Plugin 10023)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureDebugErrorsScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureDebugErrorsScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10023/

### How it detects

Passive; sets evidence; threshold: low

_threshold: low_

