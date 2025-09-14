---
aliases:
  - "STS-0035"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10035"
name: "Strict-Transport-Security Header"
occurrenceCount: "0"
pluginId: "10035"
schemaVersion: "v1"
sourceTool: "zap"
---

# Strict-Transport-Security Header (Plugin 10035)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/StrictTransportSecurityScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/StrictTransportSecurityScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10035/

### How it detects

Passive; checks headers: Location; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- header:Location
- regex:\\bmax-age\\s*=\\s*\'*\
- regex:\\bmax-age\\s*=\\s*\'*\

