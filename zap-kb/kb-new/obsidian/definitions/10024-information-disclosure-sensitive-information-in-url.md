---
aliases:
  - "IDSIU-0024"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10024"
name: "Information Disclosure - Sensitive Information in URL"
occurrenceCount: "0"
pluginId: "10024"
schemaVersion: "v1"
sourceTool: "zap"
---

# Information Disclosure - Sensitive Information in URL (Plugin 10024)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureInUrlScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureInUrlScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10024/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b
- regex:\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b

