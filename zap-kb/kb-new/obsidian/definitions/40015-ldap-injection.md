---
aliases:
  - "LI-0015"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40015"
name: "LDAP Injection"
occurrenceCount: "0"
pluginId: "40015"
schemaVersion: "v1"
sourceTool: "zap"
---

# LDAP Injection (Plugin 40015)

## Detection logic

- Logic: active
- Add-on: ascanrulesAlpha
- Source path: `zap-extensions/addOns/ascanrulesAlpha/src/main/java/org/zaproxy/zap/extension/ascanrulesAlpha/LdapInjectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesAlpha/src/main/java/org/zaproxy/zap/extension/ascanrulesAlpha/LdapInjectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40015/

### How it detects

Active; sets evidence

### References
- https://owasp.org/www-community/attacks/LDAP_Injection
- https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html

