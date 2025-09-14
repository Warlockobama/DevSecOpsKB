---
aliases:
  - "UH-0057"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10057"
name: "Username Hash Found"
occurrenceCount: "0"
pluginId: "10057"
schemaVersion: "v1"
sourceTool: "zap"
---

# Username Hash Found (Plugin 10057)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UsernameIdorScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/UsernameIdorScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10057/

### How it detects

Passive; sets evidence

### References
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.html

