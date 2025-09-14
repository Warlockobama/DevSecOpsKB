---
aliases:
  - "WFD-0030"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90030"
name: "WSDL File Detection"
occurrenceCount: "0"
pluginId: "90030"
schemaVersion: "v1"
sourceTool: "zap"
---

# WSDL File Detection (Plugin 90030)

## Detection logic

- Logic: unknown
- Add-on: soap
- Source path: `zap-extensions/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/WSDLFilePassiveScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/WSDLFilePassiveScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90030/

### How it detects

Unknown; checks headers: Content-Type; sets evidence

Signals:
- header:Content-Type

