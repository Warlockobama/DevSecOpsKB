---
aliases:
  - "CWSA-0054"
cweId: "1275"
cweUri: "https://cwe.mitre.org/data/definitions/1275.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10054"
name: "Cookie without SameSite Attribute"
occurrenceCount: "2"
pluginId: "10054"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "2"
wascId: "13"
---

# Cookie without SameSite Attribute (Plugin 10054)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieSameSiteScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CookieSameSiteScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10054/

### How it detects

Passive; checks headers: Set-Cookie; sets evidence; threshold: high

_threshold: high_

Signals:
- header:Set-Cookie

## Remediation

Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.

### References
- https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site

## Issues

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8a2f4e316ea1b881.md|Issue fin-8a2f4e316ea1b881]]
#### Observations
- [[occurrences/occ-24cfb7b76bf72a91.md|leakedcookie[msc]]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-76d703bef9c88949.md|Issue fin-76d703bef9c88949]]
#### Observations
- [[occurrences/occ-90d8a3de095d309c.md|leakedinresource[msc]]]

