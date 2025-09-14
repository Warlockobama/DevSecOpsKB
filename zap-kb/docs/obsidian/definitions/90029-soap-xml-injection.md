---
aliases:
  - "SXI-0029"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90029"
name: "SOAP XML Injection"
occurrenceCount: "0"
pluginId: "90029"
schemaVersion: "v1"
sourceTool: "zap"
---

# SOAP XML Injection (Plugin 90029)

## Detection logic

- Logic: unknown
- Add-on: soap
- Source path: `zap-extensions/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/SOAPXMLInjectionActiveScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/SOAPXMLInjectionActiveScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90029/

### How it detects

Unknown; checks headers: SOAPAction

Signals:
- header:SOAPAction

