---
aliases:
  - "IDSIH-0025"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10025"
name: "Information Disclosure - Sensitive Information in HTTP Referrer Header"
occurrenceCount: "0"
pluginId: "10025"
schemaVersion: "v1"
sourceTool: "zap"
---

# Information Disclosure - Sensitive Information in HTTP Referrer Header (Plugin 10025)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureReferrerScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InformationDisclosureReferrerScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10025/

### How it detects

Passive; checks headers: Referer; uses regex patterns; sets evidence

Signals:
- header:Referer
- regex:\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b
- regex:\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b

