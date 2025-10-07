---
aliases:
  - "CWD-0055"
cweId: "693"
cweUri: "https://cwe.mitre.org/data/definitions/693.html"
generatedAt: "2025-09-18T15:36:59Z"
id: "def-10055"
name: "CSP: Wildcard Directive"
occurrenceCount: "11"
pluginId: "10055"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "11"
wascId: "15"
---

# CSP: Wildcard Directive (Plugin 10055)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentSecurityPolicyScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentSecurityPolicyScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10055/

### How it detects

Passive; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- regex:^
  - hint: Regular expression; see pattern for details.

## Remediation

Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### References
- http://www.w3.org/TR/CSP2/
- http://www.w3.org/TR/CSP/
- http://caniuse.com/#search=content+security+policy
- http://content-security-policy.com/
- https://github.com/shapesecurity/salvation
- https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources

## Issues

### GET https://test.qnod.cms.gov/api/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eaf6f4aa3066d608.md|Issue fin-eaf6f4aa3066d608]]
#### Observations
- [[occurrences/occ-3a2f86157b81e3d6.md|api[csp]]]

### HEAD https://test.qnod.cms.gov/api/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a21e240d80a12d8f.md|Issue fin-a21e240d80a12d8f]]
#### Observations
- [[occurrences/occ-a83a17c5c5834514.md|api[csp]]]

### OPTIONS https://test.qnod.cms.gov/api/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f4545ba7182ae74c.md|Issue fin-f4545ba7182ae74c]]
#### Observations
- [[occurrences/occ-b7f9a26103397502.md|api[csp]]]

### POST https://test.qnod.cms.gov/api/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-98f0b057dc7b5179.md|Issue fin-98f0b057dc7b5179]]
#### Observations
- [[occurrences/occ-8218859e28c51cb5.md|api[csp]]]

### GET https://test.qnod.cms.gov/api/aui/summary  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ed3ec70d2255cb3e.md|Issue fin-ed3ec70d2255cb3e]]
#### Observations
- [[occurrences/occ-57564a35b58df34a.md|summary[csp]]]

### POST https://test.qnod.cms.gov/api/auth/callback  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e61cd65eaa3517ea.md|Issue fin-e61cd65eaa3517ea]]
#### Observations
- [[occurrences/occ-c904576d25dd0dbd.md|callback[csp]]]

### GET https://test.qnod.cms.gov/api/auth/verify  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7730891c16ea4e96.md|Issue fin-7730891c16ea4e96]]
#### Observations
- [[occurrences/occ-c50b99c7320018f3.md|verify[csp]]]

### GET https://test.qnod.cms.gov/api/ui/detail/1176aa66-7cef-4324-8c1e-72597f63c9b7  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1e23d41b0b042bd5.md|Issue fin-1e23d41b0b042bd5]]
#### Observations
- [[occurrences/occ-54be5cc21835c278.md|1176aa66-7cef-4324-…1e-72597f63c9b7[csp]]]

### GET https://test.qnod.cms.gov/api/ui/detail/5ca7d43b-4785-4e3b-be8a-f34f68f1c3e2  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-58d3f658c5af5beb.md|Issue fin-58d3f658c5af5beb]]
#### Observations
- [[occurrences/occ-af117d53fcf7e70a.md|5ca7d43b-4785-4e3b-…8a-f34f68f1c3e2[csp]]]

### GET https://test.qnod.cms.gov/api/ui/detail/8a6b4117-d248-40f5-a8d8-545d0843dbf  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c219fcc9f6071e20.md|Issue fin-c219fcc9f6071e20]]
#### Observations
- [[occurrences/occ-556d38ac4de630a4.md|8a6b4117-d248-40f5-a8d8-545d0843dbf[csp]]]

### GET https://test.qnod.cms.gov/api/ui/summary  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-419c030219a5483a.md|Issue fin-419c030219a5483a]]
#### Observations
- [[occurrences/occ-9c4d5327c8713ca5.md|summary[csp]]]

