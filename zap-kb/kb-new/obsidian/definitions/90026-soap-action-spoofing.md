---
aliases:
  - "SAS-0026"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90026"
name: "SOAP Action Spoofing"
occurrenceCount: "0"
pluginId: "90026"
schemaVersion: "v1"
sourceTool: "zap"
---

# SOAP Action Spoofing (Plugin 90026)

## Detection logic

- Logic: active
- Add-on: soap
- Source path: `zap-extensions/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/SOAPActionSpoofingActiveScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/soap/src/main/java/org/zaproxy/zap/extension/soap/SOAPActionSpoofingActiveScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90026/

### How it detects

Active; checks headers: SOAPAction, Content-Type

Signals:
- header:SOAPAction
- header:Content-Type

### References
- https://www.nds.ruhr-uni-bochum.de/media/nds/veroeffentlichungen/2012/07/11/camera-ready.pdf

