---
aliases:
  - "XCTO-0021"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10021"
name: "X-Content-Type-Options Header Missing"
occurrenceCount: "0"
pluginId: "10021"
schemaVersion: "v1"
sourceTool: "zap"
---

# X-Content-Type-Options Header Missing (Plugin 10021)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XContentTypeOptionsScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XContentTypeOptionsScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10021/

### How it detects

Passive; checks headers: X-Content-Type-Options; sets evidence

Signals:
- header:X-Content-Type-Options

### References
- https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941%28v=vs.85%29
- https://owasp.org/www-community/Security_Headers

