---
aliases:
  - "CDM-0098"
cweId: "264"
cweUri: "https://cwe.mitre.org/data/definitions/264.html"
generatedAt: "2025-09-18T15:36:59Z"
id: "def-10098"
name: "Cross-Domain Misconfiguration"
occurrenceCount: "2"
pluginId: "10098"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "2"
wascId: "14"
---

# Cross-Domain Misconfiguration (Plugin 10098)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CrossDomainMisconfigurationScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CrossDomainMisconfigurationScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10098/

### How it detects

Passive; checks headers: Access-Control-Allow-Origin, Access-Control-Allow-Headers, Access-Control-Allow-Methods; sets evidence

Signals:
- header:Access-Control-Allow-Origin
- header:Access-Control-Allow-Headers
- header:Access-Control-Allow-Methods
- header:Access-Control-Expose-Headers

## Remediation

Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

### References
- https://vulncat.fortify.com/en/detail?id=desc.config.dotnet.html5_overly_permissive_cors_policy
- https://vulncat.fortify.com/en/detail?category=HTML5&amp;subcategory=Overly%20Permissive%20CORS%20Policy

## Issues

### GET https://test.qnod.cms.gov/api/auth/verify  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-323d0dd4f7a95aa4.md|Issue fin-323d0dd4f7a95aa4]]
#### Observations
- [[occurrences/occ-2b89f78c33b25c8f.md|verify]]

### GET https://test.qnod.cms.gov/api/ui/summary  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5a88fcc1045e6002.md|Issue fin-5a88fcc1045e6002]]
#### Observations
- [[occurrences/occ-4091585b4eb31020.md|summary]]

