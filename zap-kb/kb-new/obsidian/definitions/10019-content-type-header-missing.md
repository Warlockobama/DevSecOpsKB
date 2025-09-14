---
aliases:
  - "CT-0019"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10019"
name: "Content-Type Header Missing"
occurrenceCount: "0"
pluginId: "10019"
schemaVersion: "v1"
sourceTool: "zap"
---

# Content-Type Header Missing (Plugin 10019)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentTypeMissingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentTypeMissingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10019/

### How it detects

Passive; checks headers: Content-Type

Signals:
- header:Content-Type

