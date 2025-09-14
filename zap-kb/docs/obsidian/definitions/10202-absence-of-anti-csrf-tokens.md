---
aliases:
  - "AACT-0202"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10202"
name: "Absence of Anti-CSRF Tokens"
occurrenceCount: "0"
pluginId: "10202"
schemaVersion: "v1"
sourceTool: "zap"
---

# Absence of Anti-CSRF Tokens (Plugin 10202)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CsrfCountermeasuresScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CsrfCountermeasuresScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10202/

### How it detects

Passive; sets evidence; threshold: high

_threshold: high_

