---
aliases:
  - "CI-0003"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40003"
name: "CRLF Injection"
occurrenceCount: "0"
pluginId: "40003"
schemaVersion: "v1"
sourceTool: "zap"
---

# CRLF Injection (Plugin 40003)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CrlfInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CrlfInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40003/

### How it detects

Active; uses regex patterns; sets evidence

Signals:
- regex:\\nSet-cookie: 

### References
- https://owasp.org/www-community/vulnerabilities/CRLF_Injection
- https://cwe.mitre.org/data/definitions/113.html

