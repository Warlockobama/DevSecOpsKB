---
aliases:
  - "CSSR-0012"
cweId: "79"
cweUri: "https://cwe.mitre.org/data/definitions/79.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-40012"
name: "Cross Site Scripting (Reflected)"
occurrenceCount: "60"
pluginId: "40012"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "60"
wascId: "8"
---

# Cross Site Scripting (Reflected) (Plugin 40012)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CrossSiteScriptingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CrossSiteScriptingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40012/

### How it detects

Active; sets evidence; threshold: low

_threshold: low_

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

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=%22+onMouseOver%3D%22alert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-40e80bde3d626a84.md|Issue fin-40e80bde3d626a84]]
#### Observations
- [[occurrences/occ-e2b9ee2d64c729ae.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=%22+onMouseOver%3D%22alert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f88981287cbd15c6.md|Issue fin-f88981287cbd15c6]]
#### Observations
- [[occurrences/occ-ea9f9c08b9582afc.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=%22+onMouseOver%3D%22alert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b72a79c558a8e93a.md|Issue fin-b72a79c558a8e93a]]
#### Observations
- [[occurrences/occ-4c6f0590e283976e.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=accesskey%3D%27x%27+onclick%3D%27alert%281%29%27+b  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f5fb0c0d3d41c2de.md|Issue fin-f5fb0c0d3d41c2de]]
#### Observations
- [[occurrences/occ-c5a9f9f06221e500.md|attribute_name[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=%22+onMouseOver%3D%22alert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-34b271848d615dbc.md|Issue fin-34b271848d615dbc]]
#### Observations
- [[occurrences/occ-acb4ae11d88c3632.md|attribute_quoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=%22+src%3Dhttp%3A%2F%2Fbadsite.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-95011af252794f39.md|Issue fin-95011af252794f39]]
#### Observations
- [[occurrences/occ-f25ace59750765bb.md|attribute_script[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=%27+onMouseOver%3D%27alert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-987e0638e44ab5a7.md|Issue fin-987e0638e44ab5a7]]
#### Observations
- [[occurrences/occ-28b28b7e0eaa9e98.md|attribute_singlequoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=+onMouseOver%3Dalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3a712b079906867d.md|Issue fin-3a712b079906867d]]
#### Observations
- [[occurrences/occ-ec4c2e9eba969ac3.md|attribute_unquoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=javascript%3Aalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-33fdbdf055a5fe6d.md|Issue fin-33fdbdf055a5fe6d]]
#### Observations
- [[occurrences/occ-f5a0b7aea1b18b84.md|css_import[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=%3Balert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef5a6a989e9fd676.md|Issue fin-ef5a6a989e9fd676]]
#### Observations
- [[occurrences/occ-eed789e5b8ce78f3.md|js_assignment[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=%22%3Balert%281%29%3B%22  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9c8501b515d58fef.md|Issue fin-9c8501b515d58fef]]
#### Observations
- [[occurrences/occ-487356e1c0565c81.md|js_comment[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=%3Balert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1fcdf439722bae20.md|Issue fin-1fcdf439722bae20]]
#### Observations
- [[occurrences/occ-3b6725fda646d189.md|js_eval[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=%22%3Balert%281%29%3B%22  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-854cb13a2afa1269.md|Issue fin-854cb13a2afa1269]]
#### Observations
- [[occurrences/occ-1c19d03d7b28939d.md|js_quoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=%27%3Balert%281%29%3B%27  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d8835fdb6f4086f5.md|Issue fin-d8835fdb6f4086f5]]
#### Observations
- [[occurrences/occ-71ae4775361f157d.md|js_singlequoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=%3Balert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d90449889e0ae0ea.md|Issue fin-d90449889e0ae0ea]]
#### Observations
- [[occurrences/occ-42c434fa7487a998.md|js_slashquoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=tag+accesskey%3D%27x%27+onclick%3D%27alert%281%29%27+b  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce5ed56ade7ac758.md|Issue fin-ce5ed56ade7ac758]]
#### Observations
- [[occurrences/occ-509518001ed799c5.md|tagname[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=%3Balert%281%29  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5f4dd395ff356902.md|Issue fin-5f4dd395ff356902]]
#### Observations
- [[occurrences/occ-2e5e059b3c35a36a.md|DOUBLE_QUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=%3Balert%281%29  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ecf1fd94982fd8ad.md|Issue fin-ecf1fd94982fd8ad]]
#### Observations
- [[occurrences/occ-b086b58e71b6b3ad.md|SINGLE_QUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=%3Balert%281%29  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7ab8b34a248c3bb7.md|Issue fin-7ab8b34a248c3bb7]]
#### Observations
- [[occurrences/occ-955341d689d73a22.md|UNQUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-22f2773b3b3a00b0.md|Issue fin-22f2773b3b3a00b0]]
#### Observations
- [[occurrences/occ-451ed46faa914df5.md|DoubleQuoteSinglequote[q]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0740eb768764ccf7.md|Issue fin-0740eb768764ccf7]]
#### Observations
- [[occurrences/occ-60bbed4e65f6c198.md|SpaceDoubleQuoteSlashEquals[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=accesskey%3D%27x%27+onclick%3D%27alert%281%29%27+b  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ab15390ce460e969.md|Issue fin-ab15390ce460e969]]
#### Observations
- [[occurrences/occ-a2c66a818d0f2cae.md|attribute_name[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=%22%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c79cd8ac4705e2a3.md|Issue fin-c79cd8ac4705e2a3]]
#### Observations
- [[occurrences/occ-10fd3657b16bef70.md|attribute_quoted[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=%22+src%3Dhttp%3A%2F%2Fbadsite.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-13f6ee64f157f16d.md|Issue fin-13f6ee64f157f16d]]
#### Observations
- [[occurrences/occ-8f7c3b316e770ca9.md|attribute_script[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=%27%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e18a3e7665ee4fa2.md|Issue fin-e18a3e7665ee4fa2]]
#### Observations
- [[occurrences/occ-b6050eefa72ef83c.md|attribute_singlequoted[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-892b526ea62cdf51.md|Issue fin-892b526ea62cdf51]]
#### Observations
- [[occurrences/occ-044ce44857b6bb1f.md|attribute_unquoted[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/400?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-24a70c66739e75a2.md|Issue fin-24a70c66739e75a2]]
#### Observations
- [[occurrences/occ-c546ba3592abab2b.md|400[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/401?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ebd6de9fae689d9.md|Issue fin-0ebd6de9fae689d9]]
#### Observations
- [[occurrences/occ-75267e47db5ae654.md|401[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/403?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d35fb4b2d67a8eaf.md|Issue fin-d35fb4b2d67a8eaf]]
#### Observations
- [[occurrences/occ-3e139a294722703c.md|403[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/404?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-28d24c0c08dc27c9.md|Issue fin-28d24c0c08dc27c9]]
#### Observations
- [[occurrences/occ-63f93d7da20ce240.md|404[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/500?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-292bca822fe8faf9.md|Issue fin-292bca822fe8faf9]]
#### Observations
- [[occurrences/occ-e496b2ab4bff1cbe.md|500[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-68b49be598ce516c.md|Issue fin-68b49be598ce516c]]
#### Observations
- [[occurrences/occ-b0d9e39d17dc40d2.md|body[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=--%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3C%21--  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eebb01ae54a38b1c.md|Issue fin-eebb01ae54a38b1c]]
#### Observations
- [[occurrences/occ-b116f07c773e9186.md|body_comment[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=%3C%2Fstyle%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cstyle%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4c067f9fa187136c.md|Issue fin-4c067f9fa187136c]]
#### Observations
- [[occurrences/occ-f1fc26122b7ac506.md|css_style[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=%3C%2Fstyle%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cstyle%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f40f0c4797e0d602.md|Issue fin-f40f0c4797e0d602]]
#### Observations
- [[occurrences/occ-ed35cf4fb4101933.md|css_style_font_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=%3C%2Fstyle%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cstyle%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5c6cbe43565d58c1.md|Issue fin-5c6cbe43565d58c1]]
#### Observations
- [[occurrences/occ-6c9800d2568f2595.md|css_style_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=%3C%2Fhead%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Chead%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a1347812a14b7276.md|Issue fin-a1347812a14b7276]]
#### Observations
- [[occurrences/occ-e61e87cf05fbe9f7.md|head[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=%27+src%3Dhttp%3A%2F%2Fbadsite.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c3f4c56d0e5d24bd.md|Issue fin-c3f4c56d0e5d24bd]]
#### Observations
- [[occurrences/occ-75d0b7e28141a52b.md|iframe_attribute_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=%22+src%3Dhttp%3A%2F%2Fbadsite.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8696804db4366677.md|Issue fin-8696804db4366677]]
#### Observations
- [[occurrences/occ-0f50779c7eeded2d.md|iframe_srcdoc[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=%3C%2Fscript%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cscript%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c062f77d9430e37d.md|Issue fin-c062f77d9430e37d]]
#### Observations
- [[occurrences/occ-8156ef466c327b4d.md|js_assignment[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=%22%3Balert%281%29%3B%22  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-47f216115fca1677.md|Issue fin-47f216115fca1677]]
#### Observations
- [[occurrences/occ-005d9383c23c2bbf.md|js_comment[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=%22%3Balert%281%29%3B%22  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-78988e9b3206236f.md|Issue fin-78988e9b3206236f]]
#### Observations
- [[occurrences/occ-7b46b6800c5a08d5.md|js_eval[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=%22%3Balert%281%29%3B%22  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bc653de83c30b3f4.md|Issue fin-bc653de83c30b3f4]]
#### Observations
- [[occurrences/occ-5d422cb875b538e1.md|js_quoted_string[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=%27%3Balert%281%29%3B%27  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fa1d37ab871f4a04.md|Issue fin-fa1d37ab871f4a04]]
#### Observations
- [[occurrences/occ-af43afa5b7aa9e50.md|js_singlequoted_string[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=%3C%2Fscript%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cscript%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b87b842e18fda4e5.md|Issue fin-b87b842e18fda4e5]]
#### Observations
- [[occurrences/occ-e6c8fd0d715c8ed6.md|js_slashquoted_string[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8ab83c18fe5c7bf5.md|Issue fin-8ab83c18fe5c7bf5]]
#### Observations
- [[occurrences/occ-7e7b99be8f546ea0.md|json[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=%3C%2Fnoscript%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Cnoscript%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9bc1f534cd737779.md|Issue fin-9bc1f534cd737779]]
#### Observations
- [[occurrences/occ-3b9f462336d9c6f2.md|noscript[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=%27%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1bff3fba3a64b6a6.md|Issue fin-1bff3fba3a64b6a6]]
#### Observations
- [[occurrences/occ-438834ebf89e575a.md|style_attribute_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-21a5791396e87841.md|Issue fin-21a5791396e87841]]
#### Observations
- [[occurrences/occ-3b3cb73f5a88e727.md|tagname[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=tag+accesskey%3D%27x%27+onclick%3D%27alert%281%29%27+b  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6949d5ca7b8ba39c.md|Issue fin-6949d5ca7b8ba39c]]
#### Observations
- [[occurrences/occ-7e44c5200c9b6ebb.md|tagname[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=%3C%2Ftextarea%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Ctextarea%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f1ee6c6e2967ba7d.md|Issue fin-f1ee6c6e2967ba7d]]
#### Observations
- [[occurrences/occ-4cf9f3a385f01a94.md|textarea[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=%27%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f61da2205aa1c9cc.md|Issue fin-f61da2205aa1c9cc]]
#### Observations
- [[occurrences/occ-26f6f74bcbb8906c.md|textarea_attribute_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=%3C%2Ftitle%3E%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E%3Ctitle%3E  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-26e750f92b1a382b.md|Issue fin-26e750f92b1a382b]]
#### Observations
- [[occurrences/occ-8e20c62b50da8db0.md|title[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=javascript%3Aalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-afa33ee53f14acfe.md|Issue fin-afa33ee53f14acfe]]
#### Observations
- [[occurrences/occ-f7aea919df01894c.md|css_import[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=javascript%3Aalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-15257132d4440aa2.md|Issue fin-15257132d4440aa2]]
#### Observations
- [[occurrences/occ-ddf9fd361d4d6687.md|href[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=javascript%3Aalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c9b604938bfa597b.md|Issue fin-c9b604938bfa597b]]
#### Observations
- [[occurrences/occ-a71586dc76b6b484.md|object_data[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=javascript%3Aalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a977b39f9fe28700.md|Issue fin-a977b39f9fe28700]]
#### Observations
- [[occurrences/occ-6dc39e1091febf0b.md|script_src[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=javascript%3Aalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e72fae2db2a345a5.md|Issue fin-e72fae2db2a345a5]]
#### Observations
- [[occurrences/occ-e2754ce6f7d70428.md|application_x-shockwave-flash[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=javascript%3Aalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-83420c8b2ffa98dd.md|Issue fin-83420c8b2ffa98dd]]
#### Observations
- [[occurrences/occ-532dc81cc3f6f020.md|object_raw[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=javascript%3Aalert%281%29%3B  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dc1963c05a814722.md|Issue fin-dc1963c05a814722]]
#### Observations
- [[occurrences/occ-be0bc7d42f83a3bd.md|script[q]]]

