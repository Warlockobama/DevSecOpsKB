---
aliases:
  - "IDSIB-0001"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-120001"
name: "Information Disclosure - Sensitive Information in Browser Storage"
occurrenceCount: "0"
pluginId: "120001"
schemaVersion: "v1"
sourceTool: "zap"
---

# Information Disclosure - Sensitive Information in Browser Storage (Plugin 120001)

## Detection logic

- Logic: passive
- Add-on: client
- Source path: `zap-extensions/addOns/client/src/main/java/org/zaproxy/addon/client/pscan/SensitiveInfoInStorageScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/client/src/main/java/org/zaproxy/addon/client/pscan/SensitiveInfoInStorageScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/120001/

### How it detects

Passive; uses regex patterns

Signals:
- regex:\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b
- regex:\\b\\d{3}-\\d{2}-\\d{4}\\b

