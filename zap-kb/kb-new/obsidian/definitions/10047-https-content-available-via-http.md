---
aliases:
  - "HCAVH-0047"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10047"
name: "HTTPS Content Available via HTTP"
occurrenceCount: "0"
pluginId: "10047"
schemaVersion: "v1"
sourceTool: "zap"
---

# HTTPS Content Available via HTTP (Plugin 10047)

## Detection logic

- Logic: passive
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/HttpsAsHttpScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/HttpsAsHttpScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10047/

### How it detects

Passive; sets evidence

### References
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- https://owasp.org/www-community/Security_Headers
- https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
- https://caniuse.com/stricttransportsecurity
- https://datatracker.ietf.org/doc/html/rfc6797

