---
aliases:
  - "CSPC-0038"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10038"
name: "Content Security Policy (CSP) Header Not Set"
occurrenceCount: "0"
pluginId: "10038"
schemaVersion: "v1"
sourceTool: "zap"
---

# Content Security Policy (CSP) Header Not Set (Plugin 10038)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentSecurityPolicyMissingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentSecurityPolicyMissingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10038/

### How it detects

Passive; threshold: low

_threshold: low_

