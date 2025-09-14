---
aliases:
  - "AC-0020"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10020"
name: "Anti-clickjacking Header"
occurrenceCount: "0"
pluginId: "10020"
schemaVersion: "v1"
sourceTool: "zap"
---

# Anti-clickjacking Header (Plugin 10020)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/AntiClickjackingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/AntiClickjackingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10020/

### How it detects

Passive; checks headers: X-Frame-Option; sets evidence; threshold: low

_threshold: low_

Signals:
- header:X-Frame-Option

