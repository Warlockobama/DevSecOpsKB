---
aliases:
  - "IJV-0001"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-90001"
name: "Insecure JSF ViewState"
occurrenceCount: "0"
pluginId: "90001"
schemaVersion: "v1"
sourceTool: "zap"
---

# Insecure JSF ViewState (Plugin 90001)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InsecureJsfViewStatePassiveScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InsecureJsfViewStatePassiveScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90001/

### How it detects

Passive

