---
aliases:
  - "HDMM-0097"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10097"
name: "Hash Disclosure - MD4 / MD5"
occurrenceCount: "0"
pluginId: "10097"
schemaVersion: "v1"
sourceTool: "zap"
---

# Hash Disclosure - MD4 / MD5 (Plugin 10097)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/HashDisclosureScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/HashDisclosureScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10097/

### How it detects

Passive; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- regex:\\b[A-Za-z0-9/]{13}\\b
- regex:\\$LM\\$[a-f0-9]{16}

