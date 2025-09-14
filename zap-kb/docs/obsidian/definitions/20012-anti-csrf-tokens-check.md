---
aliases:
  - "ACTC-0012"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-20012"
name: "Anti-CSRF Tokens Check"
occurrenceCount: "0"
pluginId: "20012"
schemaVersion: "v1"
sourceTool: "zap"
---

# Anti-CSRF Tokens Check (Plugin 20012)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/CsrfTokenScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/CsrfTokenScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/20012/

### How it detects

Active; sets evidence; threshold: high

_threshold: high_

