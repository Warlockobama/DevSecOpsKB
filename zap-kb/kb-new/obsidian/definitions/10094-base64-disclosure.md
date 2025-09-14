---
aliases:
  - "BD-0094"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10094"
name: "Base64 Disclosure"
occurrenceCount: "0"
pluginId: "10094"
schemaVersion: "v1"
sourceTool: "zap"
---

# Base64 Disclosure (Plugin 10094)

## Detection logic

- Logic: passive
- Add-on: pscanrulesAlpha
- Source path: `zap-extensions/addOns/pscanrulesAlpha/src/main/java/org/zaproxy/zap/extension/pscanrulesAlpha/Base64Disclosure.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesAlpha/src/main/java/org/zaproxy/zap/extension/pscanrulesAlpha/Base64Disclosure.java
- Docs: https://www.zaproxy.org/docs/alerts/10094/

### How it detects

Passive; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- regex:[a-zA-Z0-9\\+\\\\/]{30,}={1,2}
- regex:[a-zA-Z0-9\\+\\\\/]{30,}={0,2}

