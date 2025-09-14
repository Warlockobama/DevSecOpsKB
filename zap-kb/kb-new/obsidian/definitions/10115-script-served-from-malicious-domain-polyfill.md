---
aliases:
  - "SSFMD-0115"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10115"
name: "Script Served From Malicious Domain (polyfill)"
occurrenceCount: "0"
pluginId: "10115"
schemaVersion: "v1"
sourceTool: "zap"
---

# Script Served From Malicious Domain (polyfill) (Plugin 10115)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/PolyfillCdnScriptScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/PolyfillCdnScriptScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10115/

### How it detects

Passive; sets evidence

