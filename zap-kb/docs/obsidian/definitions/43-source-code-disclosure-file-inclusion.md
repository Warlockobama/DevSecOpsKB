---
aliases:
  - "SCDFI-ef43"
cweId: "541"
cweUri: "https://cwe.mitre.org/data/definitions/541.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-43"
name: "Source Code Disclosure - File Inclusion"
occurrenceCount: "105"
pluginId: "43"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "105"
wascId: "33"
---

# Source Code Disclosure - File Inclusion (Plugin 43)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SourceCodeDisclosureFileInclusionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SourceCodeDisclosureFileInclusionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/43/

### How it detects

Active; uses regex patterns; strength: insane

_strength: insane_

Signals:
- regex:<%.*%>
  - hint: Regular expression; see pattern for details.
- regex:<?php
  - hint: Regular expression; see pattern for details.

## Remediation

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

For filenames, use stringent allow lists that limit the character set to be used. If feasible, only allow a single "." character in the filename to avoid weaknesses, and exclude directory separators such as "/". Use an allow list of allowable file extensions.

Warning: if you attempt to cleanse your data, then do so that the end result is not in the form that can be dangerous. A sanitizing mechanism can remove characters such as '.' and ';' which may be required for some exploits. An attacker can try to fool the sanitizing mechanism into "cleaning" data into a dangerous form. Suppose the attacker injects a '.' inside a filename (e.g. "sensi.tiveFile") and the sanitizing mechanism removes the character resulting in the valid filename, "sensitiveFile". If the input data are now assumed to be safe, then the file may be compromised. 

Inputs should be decoded and canonicalized to the application's current internal representation before being validated. Make sure that your application does not decode the same input twice. Such errors could be used to bypass allow list schemes by introducing dangerous inputs after they have been checked.

Use a built-in path canonicalization function (such as realpath() in C) that produces the canonical version of the pathname, which effectively removes ".." sequences and symbolic links.

Run your code using the lowest privileges that are required to accomplish the necessary tasks. If possible, create isolated accounts with limited privileges that are only used for a single task. That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations.

When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.

Run your code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by your software.

OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows you to specify restrictions on file operations.

This may not be a feasible solution, and it only limits the impact to the operating system; the rest of your application may still be subject to compromise.

### References
- https://owasp.org/www-community/attacks/Path_Traversal
- https://cwe.mitre.org/data/definitions/22.html

## Issues

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c2163e6da09dc443.md|Issue fin-c2163e6da09dc443]]
#### Observations
- [[occurrences/occ-40fe4c4fe6946715.md|1.1.5[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3bb8b95253083dc0.md|Issue fin-3bb8b95253083dc0]]
#### Observations
- [[occurrences/occ-badf5d2a2acd7056.md|1.2.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de59de74a144fec3.md|Issue fin-de59de74a144fec3]]
#### Observations
- [[occurrences/occ-e95146972806d194.md|1.2.18[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b5332d2a3ef6c7b7.md|Issue fin-b5332d2a3ef6c7b7]]
#### Observations
- [[occurrences/occ-1d0cb59f742d4445.md|1.2.19[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0b2b43cf5ec68ff2.md|Issue fin-0b2b43cf5ec68ff2]]
#### Observations
- [[occurrences/occ-de9d6c2f28e4b822.md|1.2.24[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-060f88341976b107.md|Issue fin-060f88341976b107]]
#### Observations
- [[occurrences/occ-192c4f13d1e6ae66.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-744bf9afd85e1325.md|Issue fin-744bf9afd85e1325]]
#### Observations
- [[occurrences/occ-aaa8d58ade9ca5e0.md|1.6.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bdbc1c28d927d318.md|Issue fin-bdbc1c28d927d318]]
#### Observations
- [[occurrences/occ-7798d108c250a041.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-36b23ff4ad01b599.md|Issue fin-36b23ff4ad01b599]]
#### Observations
- [[occurrences/occ-ea7f4ecfe1ef5f40.md|1.6.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-350bfa7672157b3e.md|Issue fin-350bfa7672157b3e]]
#### Observations
- [[occurrences/occ-88a5c4855ed6182e.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e35b0c2889ab6073.md|Issue fin-e35b0c2889ab6073]]
#### Observations
- [[occurrences/occ-014b3a25a310bb6f.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f55efc33f825de0.md|Issue fin-7f55efc33f825de0]]
#### Observations
- [[occurrences/occ-20b8aef6c3f99c24.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-33949aba5478387c.md|Issue fin-33949aba5478387c]]
#### Observations
- [[occurrences/occ-1c07bd874742f4fd.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-040b9a4ad2fd0973.md|Issue fin-040b9a4ad2fd0973]]
#### Observations
- [[occurrences/occ-a0b08339ec875414.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b228bc440ce9379.md|Issue fin-7b228bc440ce9379]]
#### Observations
- [[occurrences/occ-6f1f211233423efe.md|1.4.0[q]]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-34219a70d616bbb5.md|Issue fin-34219a70d616bbb5]]
#### Observations
- [[occurrences/occ-43421a36c1c69db3.md|encodeURIComponent[q]]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cd6419b306d17a8a.md|Issue fin-cd6419b306d17a8a]]
#### Observations
- [[occurrences/occ-12c1f3d1fc5a799e.md|escape[q]]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b41bffcde594b5de.md|Issue fin-b41bffcde594b5de]]
#### Observations
- [[occurrences/occ-0311740cea8e5e85.md|html_escape[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4e9114a83d937bce.md|Issue fin-4e9114a83d937bce]]
#### Observations
- [[occurrences/occ-4b6d649bf4a5a1fd.md|attribute_name[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3238eb5b49f53ce3.md|Issue fin-3238eb5b49f53ce3]]
#### Observations
- [[occurrences/occ-ec4e1ef5407d6162.md|attribute_quoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-06476178ee01ff6e.md|Issue fin-06476178ee01ff6e]]
#### Observations
- [[occurrences/occ-c5ca219afbf41ef1.md|attribute_script[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2fbff69147dd3c77.md|Issue fin-2fbff69147dd3c77]]
#### Observations
- [[occurrences/occ-08b7702c8d2c55b5.md|attribute_singlequoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-87c76f41a91b3ccc.md|Issue fin-87c76f41a91b3ccc]]
#### Observations
- [[occurrences/occ-9bc24c80667112f0.md|attribute_unquoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1385fd4397cef2c2.md|Issue fin-1385fd4397cef2c2]]
#### Observations
- [[occurrences/occ-9954cdc98ac79d54.md|body[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a5ed1a4d97293875.md|Issue fin-a5ed1a4d97293875]]
#### Observations
- [[occurrences/occ-03c0f00413cc8ba9.md|body_comment[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-586c36158d2d9716.md|Issue fin-586c36158d2d9716]]
#### Observations
- [[occurrences/occ-dcf96a9e57a85a5e.md|css_import[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fdbc091278e39511.md|Issue fin-fdbc091278e39511]]
#### Observations
- [[occurrences/occ-16b3af96f16e157a.md|css_style[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-19db7575cac6bf60.md|Issue fin-19db7575cac6bf60]]
#### Observations
- [[occurrences/occ-452d4a35ad212752.md|css_style_font_value[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d12d425c80a32617.md|Issue fin-d12d425c80a32617]]
#### Observations
- [[occurrences/occ-99f04f1e108593c2.md|css_style_value[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-556407344c682514.md|Issue fin-556407344c682514]]
#### Observations
- [[occurrences/occ-f483f7a86a940f6b.md|head[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-64c1c8225638858e.md|Issue fin-64c1c8225638858e]]
#### Observations
- [[occurrences/occ-6b1f12ee07134dd4.md|js_assignment[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e433dc61910cfc47.md|Issue fin-e433dc61910cfc47]]
#### Observations
- [[occurrences/occ-da8f891e04ede83d.md|js_comment[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3da73aab033d1537.md|Issue fin-3da73aab033d1537]]
#### Observations
- [[occurrences/occ-61acabff5f237bf8.md|js_eval[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ad7e6ad031b7abf6.md|Issue fin-ad7e6ad031b7abf6]]
#### Observations
- [[occurrences/occ-3f1e0364f03d2396.md|js_quoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2219f8b59cd8ffe7.md|Issue fin-2219f8b59cd8ffe7]]
#### Observations
- [[occurrences/occ-77a4fbbe81935a7d.md|js_singlequoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-64828363ea5132d5.md|Issue fin-64828363ea5132d5]]
#### Observations
- [[occurrences/occ-f7fb71081b2b0c88.md|js_slashquoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d2a0c8d7309c17e4.md|Issue fin-d2a0c8d7309c17e4]]
#### Observations
- [[occurrences/occ-9f420fe414c5ec88.md|tagname[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c2570e8a556b7972.md|Issue fin-c2570e8a556b7972]]
#### Observations
- [[occurrences/occ-27fe75fe6f69b5c7.md|textarea[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-82fcc2a15f251c14.md|Issue fin-82fcc2a15f251c14]]
#### Observations
- [[occurrences/occ-a7d82c5e050ea0e9.md|attribute_name[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ba248d09ff4da4a3.md|Issue fin-ba248d09ff4da4a3]]
#### Observations
- [[occurrences/occ-d567bdc4f6cb688d.md|attribute_quoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-076ab372110d58fa.md|Issue fin-076ab372110d58fa]]
#### Observations
- [[occurrences/occ-853d47629cd55a00.md|attribute_script[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-801655de067d814e.md|Issue fin-801655de067d814e]]
#### Observations
- [[occurrences/occ-5ce79488209a8020.md|attribute_singlequoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e95937c03a7ee077.md|Issue fin-e95937c03a7ee077]]
#### Observations
- [[occurrences/occ-25eaa24e4d1ce7a1.md|attribute_unquoted[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-77fb1374abb1af76.md|Issue fin-77fb1374abb1af76]]
#### Observations
- [[occurrences/occ-f0f2762b4ef9a31b.md|body[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f183fb7b6d52a0d9.md|Issue fin-f183fb7b6d52a0d9]]
#### Observations
- [[occurrences/occ-99639eb5bf9f4907.md|body_comment[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c8b63d5ce1dbba09.md|Issue fin-c8b63d5ce1dbba09]]
#### Observations
- [[occurrences/occ-ed1adfc1f026b2cb.md|css_import[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b20974e26a5a6c1a.md|Issue fin-b20974e26a5a6c1a]]
#### Observations
- [[occurrences/occ-7daff7f7e15dc909.md|css_style[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e5cc9ba127a75547.md|Issue fin-e5cc9ba127a75547]]
#### Observations
- [[occurrences/occ-c310b913ad95b64f.md|css_style_font_value[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_value?q=a&escape=HTML_ESCAPE  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-efb14bad704bc870.md|Issue fin-efb14bad704bc870]]
#### Observations
- [[occurrences/occ-a3a998b926557daf.md|css_style_value[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d8e66f3157c23880.md|Issue fin-d8e66f3157c23880]]
#### Observations
- [[occurrences/occ-3efbfa632e74479a.md|head[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5c2bfb5c3e1e99ed.md|Issue fin-5c2bfb5c3e1e99ed]]
#### Observations
- [[occurrences/occ-187f99fea7781a00.md|js_assignment[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b0889b4d7d93af23.md|Issue fin-b0889b4d7d93af23]]
#### Observations
- [[occurrences/occ-8e0c814b4911d218.md|js_comment[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3a23aaa8f84e2a3a.md|Issue fin-3a23aaa8f84e2a3a]]
#### Observations
- [[occurrences/occ-ef79e03d3a2242a6.md|js_eval[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5864b55d10915aad.md|Issue fin-5864b55d10915aad]]
#### Observations
- [[occurrences/occ-1ad931e696f5ac92.md|js_quoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-158782edebdaec7d.md|Issue fin-158782edebdaec7d]]
#### Observations
- [[occurrences/occ-9b0511208c3c0530.md|js_singlequoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-83c76b397f0a7208.md|Issue fin-83c76b397f0a7208]]
#### Observations
- [[occurrences/occ-32338749141153a8.md|js_slashquoted_string[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4223a686e18f39bc.md|Issue fin-4223a686e18f39bc]]
#### Observations
- [[occurrences/occ-4da68a1de6fc9fc5.md|tagname[q]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a3b98d409e3c7094.md|Issue fin-a3b98d409e3c7094]]
#### Observations
- [[occurrences/occ-f29e8184f0762cfd.md|textarea[q]]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackIsEchoedBack?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c1eabbc95b0bf9da.md|Issue fin-c1eabbc95b0bf9da]]
#### Observations
- [[occurrences/occ-ff94463482fa76ad.md|callbackIsEchoedBack[c]]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-21c4e5b9c18a9782.md|Issue fin-21c4e5b9c18a9782]]
#### Observations
- [[occurrences/occ-e37068dd47db9f45.md|meta[q]]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f610dabe2e0e1909.md|Issue fin-f610dabe2e0e1909]]
#### Observations
- [[occurrences/occ-38214169f05851fe.md|json[q]]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/plaintext?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1c7ed80be4c4a86b.md|Issue fin-1c7ed80be4c4a86b]]
#### Observations
- [[occurrences/occ-61361bd1700e435d.md|plaintext[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d279d71b46a5da2a.md|Issue fin-d279d71b46a5da2a]]
#### Observations
- [[occurrences/occ-5f4cbfce7730ed6f.md|DOUBLE_QUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1fcfc662cc833acd.md|Issue fin-1fcfc662cc833acd]]
#### Observations
- [[occurrences/occ-9f5a5dfca77c6be9.md|SINGLE_QUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7d1afdff2dc8e45a.md|Issue fin-7d1afdff2dc8e45a]]
#### Observations
- [[occurrences/occ-70202200c264b4d6.md|UNQUOTED_ATTRIBUTE[q]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9079eafc99f7acd6.md|Issue fin-9079eafc99f7acd6]]
#### Observations
- [[occurrences/occ-e04033570c59b455.md|DoubleQuoteSinglequote[q]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7bf8fd0a83bdee16.md|Issue fin-7bf8fd0a83bdee16]]
#### Observations
- [[occurrences/occ-0a645f44a80c44d3.md|SpaceDoubleQuoteSlashEquals[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-85d13abcba503097.md|Issue fin-85d13abcba503097]]
#### Observations
- [[occurrences/occ-d1b81ed54e2ac4f9.md|attribute_name[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2f40364f0a79a4a6.md|Issue fin-2f40364f0a79a4a6]]
#### Observations
- [[occurrences/occ-b479c2e9c8ed17d7.md|attribute_quoted[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9fa4af9a2562c315.md|Issue fin-9fa4af9a2562c315]]
#### Observations
- [[occurrences/occ-b3161f6df09fffd7.md|attribute_script[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b5bfd5e48afead58.md|Issue fin-b5bfd5e48afead58]]
#### Observations
- [[occurrences/occ-0236260d2c244632.md|attribute_singlequoted[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7eccfdb6f6c332a7.md|Issue fin-7eccfdb6f6c332a7]]
#### Observations
- [[occurrences/occ-3ba49e58c298332d.md|attribute_unquoted[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-27fb44b47c006a31.md|Issue fin-27fb44b47c006a31]]
#### Observations
- [[occurrences/occ-c928dd33925de0e1.md|body[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-610bb6001867989b.md|Issue fin-610bb6001867989b]]
#### Observations
- [[occurrences/occ-8509dcba0e7c5781.md|body_comment[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f7c14b401095d3a2.md|Issue fin-f7c14b401095d3a2]]
#### Observations
- [[occurrences/occ-3d6da7594cfdf221.md|css_style[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-54c03c7626a6307d.md|Issue fin-54c03c7626a6307d]]
#### Observations
- [[occurrences/occ-028d5c9ce0917f87.md|css_style_font_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2b56d138d7165dec.md|Issue fin-2b56d138d7165dec]]
#### Observations
- [[occurrences/occ-877adc71b30213da.md|css_style_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-026e9a0930dbbe58.md|Issue fin-026e9a0930dbbe58]]
#### Observations
- [[occurrences/occ-df145f48074c9a68.md|head[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f32d36dcbf3b9baf.md|Issue fin-f32d36dcbf3b9baf]]
#### Observations
- [[occurrences/occ-d5b0d391c02e6f73.md|iframe_attribute_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4d2095e7d2464ecd.md|Issue fin-4d2095e7d2464ecd]]
#### Observations
- [[occurrences/occ-e8bc8d9523c80631.md|iframe_srcdoc[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef84504de68e5f97.md|Issue fin-ef84504de68e5f97]]
#### Observations
- [[occurrences/occ-c674fec90a9809fa.md|js_assignment[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-72c38ee8130aced7.md|Issue fin-72c38ee8130aced7]]
#### Observations
- [[occurrences/occ-e97e7a8b3b613925.md|js_comment[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a0b2488735ab9e53.md|Issue fin-a0b2488735ab9e53]]
#### Observations
- [[occurrences/occ-de82656c3b5e6238.md|js_eval[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ff4c2b33abbfb898.md|Issue fin-ff4c2b33abbfb898]]
#### Observations
- [[occurrences/occ-394b11e27f0410f8.md|js_quoted_string[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-290a7c1671bf30f8.md|Issue fin-290a7c1671bf30f8]]
#### Observations
- [[occurrences/occ-b7ba867b52b55a21.md|js_singlequoted_string[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-117848ff6a47407d.md|Issue fin-117848ff6a47407d]]
#### Observations
- [[occurrences/occ-212cfad57a897cfb.md|js_slashquoted_string[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-319f256c774e015b.md|Issue fin-319f256c774e015b]]
#### Observations
- [[occurrences/occ-98c3c3c3a49a8300.md|json[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a9c539624b70c45e.md|Issue fin-a9c539624b70c45e]]
#### Observations
- [[occurrences/occ-83af363e7a02628e.md|noscript[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4723cee324ff5dfc.md|Issue fin-4723cee324ff5dfc]]
#### Observations
- [[occurrences/occ-dd17ab87c398508e.md|style_attribute_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b8e04590900eaccf.md|Issue fin-b8e04590900eaccf]]
#### Observations
- [[occurrences/occ-ef61c27de409f288.md|tagname[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3fa38f94bfd96889.md|Issue fin-3fa38f94bfd96889]]
#### Observations
- [[occurrences/occ-cce145682ba95fd0.md|textarea[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dcc65db6ad86e6e8.md|Issue fin-dcc65db6ad86e6e8]]
#### Observations
- [[occurrences/occ-3f4dbf6ba742068d.md|textarea_attribute_value[q]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f753662186b8330a.md|Issue fin-f753662186b8330a]]
#### Observations
- [[occurrences/occ-dc0ed2aeacbfa8d3.md|title[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e34e3fb75c27f7be.md|Issue fin-e34e3fb75c27f7be]]
#### Observations
- [[occurrences/occ-4b0b0c58ccc2cf14.md|css_import[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ee59af30404aaf6.md|Issue fin-0ee59af30404aaf6]]
#### Observations
- [[occurrences/occ-e719de0267840634.md|href[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee042afb83efc3ef.md|Issue fin-ee042afb83efc3ef]]
#### Observations
- [[occurrences/occ-a67c1df4014d6d02.md|object_data[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/object_param?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-09726deb6ff851fe.md|Issue fin-09726deb6ff851fe]]
#### Observations
- [[occurrences/occ-80fc25438e05ff34.md|object_param[q]]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f4e097002755c9b4.md|Issue fin-f4e097002755c9b4]]
#### Observations
- [[occurrences/occ-d923b6e7f6325de8.md|script_src[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-40b952907943fe3f.md|Issue fin-40b952907943fe3f]]
#### Observations
- [[occurrences/occ-f289461c6e168298.md|application_x-shockwave-flash[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-87e8e4f250047396.md|Issue fin-87e8e4f250047396]]
#### Observations
- [[occurrences/occ-e933b360efa30c81.md|object_raw[q]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-adad6901247e32c9.md|Issue fin-adad6901247e32c9]]
#### Observations
- [[occurrences/occ-4e6a883dab02a374.md|script[q]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c9f5e1c5dd7840aa.md|Issue fin-c9f5e1c5dd7840aa]]
#### Observations
- [[occurrences/occ-6422fa14c23fa997.md|InCallback[q]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-75092b8507c09ad5.md|Issue fin-75092b8507c09ad5]]
#### Observations
- [[occurrences/occ-540ed98ecbccd32b.md|OtherParameter[q]]]

### GET https://public-firing-range.appspot.com/tags/multiline?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-18af5f4c0f9a80a6.md|Issue fin-18af5f4c0f9a80a6]]
#### Observations
- [[occurrences/occ-2cf50ca47babf0fe.md|multiline[q]]]

### GET https://public-firing-range.appspot.com/urldom/jsonp?callback=foobar  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6ce402b7934a4999.md|Issue fin-6ce402b7934a4999]]
#### Observations
- [[occurrences/occ-8774b5eefd2d2047.md|jsonp[c]]]

