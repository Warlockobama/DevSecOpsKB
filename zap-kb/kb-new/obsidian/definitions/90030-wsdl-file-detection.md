---
aliases:
  - "WFD-0030"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90030"
name: "WSDL File Detection"
occurrenceCount: "0"
pluginId: "90030"
schemaVersion: "v1"
sourceTool: "zap"
---

# WSDL File Detection (Plugin 90030)

## Detection logic

- Logic: passive
- Add-on: soap
- Source path: `zap-extensions/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/WSDLFilePassiveScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/WSDLFilePassiveScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90030/

### How it detects

Passive; checks headers: Content-Type; sets evidence

Signals:
- header:Content-Type

