---
aliases:
  - "RPC-0051"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10051"
name: "Relative Path Confusion"
occurrenceCount: "0"
pluginId: "10051"
schemaVersion: "v1"
sourceTool: "zap"
---

# Relative Path Confusion (Plugin 10051)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/RelativePathConfusionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/RelativePathConfusionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10051/

### How it detects

Active; uses regex patterns; sets evidence

Signals:
- regex:[a-zA-Z_-]*\\s*:\\s*url\\s*\\((?!https?:)[^/][^)]*\\)

