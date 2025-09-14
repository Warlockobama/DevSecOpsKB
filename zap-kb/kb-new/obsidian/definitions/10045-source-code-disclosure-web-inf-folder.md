---
aliases:
  - "SCDWI-0045"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10045"
name: "Source Code Disclosure - /WEB-INF Folder"
occurrenceCount: "0"
pluginId: "10045"
schemaVersion: "v1"
sourceTool: "zap"
---

# Source Code Disclosure - /WEB-INF Folder (Plugin 10045)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SourceCodeDisclosureWebInfScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SourceCodeDisclosureWebInfScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10045/

### How it detects

Active; uses regex patterns

Signals:
- regex:[0-9a-zA-Z_.]+\\.[a-zA-Z0-9_]+
- regex:^import\\s+([0-9a-zA-Z_.]+\\.[a-zA-Z0-9_]+);

