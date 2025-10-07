---
aliases:
  - "ER-0019"
cweId: "601"
cweUri: "https://cwe.mitre.org/data/definitions/601.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-20019"
name: "External Redirect"
occurrenceCount: "3"
pluginId: "20019"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "3"
wascId: "38"
---

# External Redirect (Plugin 20019)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ExternalRedirectScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/ExternalRedirectScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/20019/

### How it detects

Active; checks headers: Scheme-Https, Scheme-Http, Http; uses regex patterns; sets evidence

Signals:
- header:Scheme-Https
- header:Scheme-Http
- header:Http
- regex:(?i)location(?:\\.href)?\\s*=\\s*['\
  - hint: Regular expression; see pattern for details.
- regex:(?i)location\\.(?:replace|reload|assign)\\s*\\(\\s*['\
  - hint: Regular expression; see pattern for details.

## Remediation

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Use an allow list of approved URLs or domains to be used for redirection.

Use an intermediate disclaimer page that provides the user with a clear warning that they are leaving your site. Implement a long timeout before the redirect occurs, or force the user to click on the link. Be careful to avoid XSS problems when generating the disclaimer page.

When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.

For example, ID 1 could map to "/login.asp" and ID 2 could map to "https://www.example.com/". Features such as the ESAPI AccessReferenceMap provide this capability.

Understand all the potential areas where untrusted inputs can enter your software: parameters or arguments, cookies, anything read from the network, environment variables, reverse DNS lookups, query results, request headers, URL components, e-mail, files, databases, and any external systems that provide data to the application. Remember that such inputs may be obtained indirectly through API calls.

Many open redirect problems occur because the programmer assumed that certain inputs could not be modified, such as cookies and hidden form fields.

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/601.html

## Issues

### GET https://public-firing-range.appspot.com/redirect/parameter/NOSTARTSWITHJS?url=https%3A%2F%2F5291189068405099194.owasp.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a805abce47b5d9d9.md|Issue fin-a805abce47b5d9d9]]
#### Observations
- [[occurrences/occ-c307a6cd91a885a2.md|NOSTARTSWITHJS[u]]]

### GET https://public-firing-range.appspot.com/redirect/parameter?url=https%3A%2F%2F5291189068405099194.owasp.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bebd5828be0bad3f.md|Issue fin-bebd5828be0bad3f]]
#### Observations
- [[occurrences/occ-0249d91de9e0242f.md|parameter[u]]]

### GET https://public-firing-range.appspot.com/urldom/redirect?url=https%3A%2F%2F5291189068405099194.owasp.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-60f0ae49181eee8d.md|Issue fin-60f0ae49181eee8d]]
#### Observations
- [[occurrences/occ-36e24bc1b3f37dc2.md|redirect[u]]]

