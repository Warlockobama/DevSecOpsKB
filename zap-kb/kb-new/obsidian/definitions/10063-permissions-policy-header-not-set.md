---
aliases:
  - "PP-0063"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10063"
name: "Permissions Policy Header Not Set"
occurrenceCount: "0"
pluginId: "10063"
schemaVersion: "v1"
sourceTool: "zap"
---

# Permissions Policy Header Not Set (Plugin 10063)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/PermissionsPolicyScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/PermissionsPolicyScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10063/

### How it detects

Passive; sets evidence; threshold: low

_threshold: low_

