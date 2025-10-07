---
aliases:
  - "CN-0055"
cweId: "693"
cweUri: "https://cwe.mitre.org/data/definitions/693.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10055"
name: "CSP: Notices"
occurrenceCount: "1"
pluginId: "10055"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "1"
wascId: "15"
---

# CSP: Notices (Plugin 10055)

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
- https://www.w3.org/TR/CSP/
- https://caniuse.com/#search=content+security+policy
- https://content-security-policy.com/
- https://github.com/HtmlUnit/htmlunit-csp
- https://developers.google.com/web/fundamentals/security/csp#policy_applies_to_a_wide_variety_of_resources

## Issues

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_csp_no_frame_ancestors  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-21b2121d4ffd9bf6.md|Issue fin-21b2121d4ffd9bf6]]
#### Observations
- [[occurrences/occ-c83d43f8289b1e65.md|clickjacking_csp_no_frame_ancestors[csp]]]

