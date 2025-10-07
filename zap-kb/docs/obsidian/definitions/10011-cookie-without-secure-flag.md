---
aliases:
  - "CWSF-0011"
cweId: "614"
cweUri: "https://cwe.mitre.org/data/definitions/614.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10011"
name: "Cookie Without Secure Flag"
occurrenceCount: "2"
pluginId: "10011"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "2"
wascId: "13"
---

# Cookie Without Secure Flag (Plugin 10011)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieSecureFlagScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieSecureFlagScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10011/

### How it detects

Passive; checks headers: Set-Cookie; sets evidence

Signals:
- header:Set-Cookie

## Remediation

Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.

### References
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html

## Issues

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9b8c39662c6a40d2.md|Issue fin-9b8c39662c6a40d2]]
#### Observations
- [[occurrences/occ-b9629f253a32aeb5.md|leakedcookie[msc]]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9a27baa310b0014b.md|Issue fin-9a27baa310b0014b]]
#### Observations
- [[occurrences/occ-dd4755df231fac0c.md|leakedinresource[msc]]]

