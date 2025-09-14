---
aliases:
  - "US-0070"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10070"
name: "Use of SAML"
occurrenceCount: "0"
pluginId: "10070"
schemaVersion: "v1"
sourceTool: "zap"
---

# Use of SAML (Plugin 10070)

## Detection logic

- Logic: passive
- Add-on: saml
- Source path: `zap-extensions/addOns/saml/src/main/java/org/zaproxy/zap/extension/saml/SAMLPassiveScanner.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/saml/src/main/java/org/zaproxy/zap/extension/saml/SAMLPassiveScanner.java
- Docs: https://www.zaproxy.org/docs/alerts/10070/

### How it detects

Passive; sets evidence

