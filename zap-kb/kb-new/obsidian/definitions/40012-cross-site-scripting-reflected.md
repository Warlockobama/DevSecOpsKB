---
aliases:
  - "CSSR-0012"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40012"
name: "Cross Site Scripting (Reflected)"
occurrenceCount: "0"
pluginId: "40012"
schemaVersion: "v1"
sourceTool: "zap"
---

# Cross Site Scripting (Reflected) (Plugin 40012)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CrossSiteScriptingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CrossSiteScriptingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40012/

### How it detects

Active; sets evidence; threshold: low

_threshold: low_

### References
- https://owasp.org/www-community/attacks/xss/
- https://cwe.mitre.org/data/definitions/79.html

