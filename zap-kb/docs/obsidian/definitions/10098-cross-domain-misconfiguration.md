---
aliases:
  - "CDM-0098"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10098"
name: "Cross-Domain Misconfiguration"
occurrenceCount: "0"
pluginId: "10098"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cross-Domain Misconfiguration (Plugin 10098)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CrossDomainMisconfigurationScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CrossDomainMisconfigurationScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10098/

### How it detects

Passive; checks headers: Access-Control-Allow-Origin, Access-Control-Allow-Headers, Access-Control-Allow-Methods; sets evidence

Signals:
- header:Access-Control-Allow-Origin
- header:Access-Control-Allow-Headers
- header:Access-Control-Allow-Methods
- header:Access-Control-Expose-Headers

