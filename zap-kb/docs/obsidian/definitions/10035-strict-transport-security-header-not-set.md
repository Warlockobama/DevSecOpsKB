---
aliases:
  - "STS-0035"
cweId: "319"
cweUri: "https://cwe.mitre.org/data/definitions/319.html"
generatedAt: "2025-01-01T00:00:00Z"
id: "def-10035"
name: "Strict-Transport-Security Header Not Set"
occurrenceCount: "1"
pluginId: "10035"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "1"
wascId: "15"
---

# Strict-Transport-Security Header Not Set (Plugin 10035)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/StrictTransportSecurityScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/StrictTransportSecurityScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10035/

### How it detects

Passive; checks headers: Location; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- header:Location
- regex:\\bmax-age\\s*=\\s*\'*\
- regex:\\bmax-age\\s*=\\s*\'*\

## Remediation

Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

### References
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- https://owasp.org/www-community/Security_Headers
- https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
- https://caniuse.com/stricttransportsecurity
- https://datatracker.ietf.org/doc/html/rfc6797

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e8000985f89e454.md|Issue fin-7e8000985f89e454]]
#### Observations
- [[occurrences/occ-15c539b210fb2e85.md|public-firing-range.appspot.com/]]

