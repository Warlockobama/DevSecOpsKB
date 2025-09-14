---
aliases:
  - "SCDP-0099"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10099"
name: "Source Code Disclosure - PHP"
occurrenceCount: "0"
pluginId: "10099"
schemaVersion: "v1"
sourceTool: "zap"
---

# Source Code Disclosure - PHP (Plugin 10099)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/SourceCodeDisclosureScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/SourceCodeDisclosureScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10099/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:<\\?php\\s*.+?;\\s*\\?>
- regex:<\\?=\\s*.+?\\s*\\?>

### References
- https://www.wsj.com/articles/BL-CIOB-2999

