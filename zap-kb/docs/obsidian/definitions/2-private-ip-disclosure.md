---
aliases:
  - "PID-def2"
cweId: "497"
cweUri: "https://cwe.mitre.org/data/definitions/497.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-2"
name: "Private IP Disclosure"
occurrenceCount: "2"
pluginId: "2"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "2"
wascId: "13"
---

# Private IP Disclosure (Plugin 2)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InfoPrivateAddressDisclosureScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/InfoPrivateAddressDisclosureScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/2/

### How it detects

Passive; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- regex:(
  - hint: Regular expression; see pattern for details.

## Remediation

Remove the private IP address from the HTTP response body. For comments, use JSP/ASP/PHP comment instead of HTML/JavaScript comment which can be seen by client browsers.

### References
- https://tools.ietf.org/html/rfc1918
- https://datatracker.ietf.org/doc/html/rfc1918

## Issues

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-578303844971fb2c.md|Issue fin-578303844971fb2c]]
#### Observations
- [[occurrences/occ-f7e69a8eb4a51f77.md|badscriptimport]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-26b4154ebd992ceb.md|Issue fin-26b4154ebd992ceb]]
#### Observations
- [[occurrences/occ-31a351cb2bf1dc1f.md|badscriptimport/index.html]]

