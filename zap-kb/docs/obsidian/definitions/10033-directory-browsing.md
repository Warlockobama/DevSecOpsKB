---
aliases:
  - "DB-0033"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10033"
name: "Directory Browsing"
occurrenceCount: "0"
pluginId: "10033"
schemaVersion: "v1"
sourceTool: "zap"
---

# Directory Browsing (Plugin 10033)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/DirectoryBrowsingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/DirectoryBrowsingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10033/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:<title>Index of /[^<]+?</title>
- regex:<pre><A\\s+HREF\\s*=\\s*\

