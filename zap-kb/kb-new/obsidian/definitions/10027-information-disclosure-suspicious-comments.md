---
aliases:
  - "IDSC-0027"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10027"
name: "Information Disclosure - Suspicious Comments"
occurrenceCount: "0"
pluginId: "10027"
schemaVersion: "v1"
sourceTool: "zap"
---

# Information Disclosure - Suspicious Comments (Plugin 10027)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureSuspiciousCommentsScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureSuspiciousCommentsScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10027/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:/\\*.*?\\*/
- regex://.*

