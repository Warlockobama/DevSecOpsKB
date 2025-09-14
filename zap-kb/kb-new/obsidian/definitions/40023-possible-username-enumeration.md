---
aliases:
  - "PUE-0023"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40023"
name: "Possible Username Enumeration"
occurrenceCount: "0"
pluginId: "40023"
schemaVersion: "v1"
sourceTool: "zap"
---

# Possible Username Enumeration (Plugin 40023)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/UsernameEnumerationScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/UsernameEnumerationScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40023/

### How it detects

Active; strength: insane

_strength: insane_

### References
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account.html
- https://dl.ifip.org/db/conf/sec/sec2011/FreilingS11.pdf
- https://cwe.mitre.org/data/definitions/204.html

