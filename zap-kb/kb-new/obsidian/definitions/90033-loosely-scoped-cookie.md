---
aliases:
  - "LSC-0033"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-90033"
name: "Loosely Scoped Cookie"
occurrenceCount: "0"
pluginId: "90033"
schemaVersion: "v1"
sourceTool: "zap"
---

# Loosely Scoped Cookie (Plugin 90033)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieLooselyScopedScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieLooselyScopedScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/90033/

### How it detects

Passive

### References
- https://tools.ietf.org/html/rfc6265#section-4.1
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html
- https://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies

