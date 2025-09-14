---
aliases:
  - "SLIV3-0037"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10037"
name: "Server Leaks Information via &#34;X-Powered-By&#34; HTTP Response Header Field(s)"
occurrenceCount: "0"
pluginId: "10037"
schemaVersion: "v1"
sourceTool: "zap"
---

# Server Leaks Information via &#34;X-Powered-By&#34; HTTP Response Header Field(s) (Plugin 10037)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XPoweredByHeaderInfoLeakScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XPoweredByHeaderInfoLeakScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10037/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:^X-Powered-By.*

### References
- https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
- https://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html

