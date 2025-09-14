---
aliases:
  - "RECCD-0015"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10015"
name: "Re-examine Cache-control Directives"
occurrenceCount: "0"
pluginId: "10015"
schemaVersion: "v1"
sourceTool: "zap"
---

# Re-examine Cache-control Directives (Plugin 10015)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CacheControlScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CacheControlScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10015/

### How it detects

Passive; checks headers: Cache-Control; sets evidence; threshold: low

_threshold: low_

Signals:
- header:Cache-Control

