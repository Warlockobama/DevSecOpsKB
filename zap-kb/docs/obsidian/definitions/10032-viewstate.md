---
aliases:
  - "V-0032"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10032"
name: "Viewstate"
occurrenceCount: "0"
pluginId: "10032"
schemaVersion: "v1"
sourceTool: "zap"
---

# Viewstate (Plugin 10032)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ViewstateScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ViewstateScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10032/

### How it detects

Passive; uses regex patterns; threshold: low

_threshold: low_

Signals:
- regex:__.*
- regex:[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}

