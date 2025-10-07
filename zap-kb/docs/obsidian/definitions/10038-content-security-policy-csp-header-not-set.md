---
aliases:
  - "CSPC-0038"
cweId: "693"
cweUri: "https://cwe.mitre.org/data/definitions/693.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10038"
name: "Content Security Policy (CSP) Header Not Set"
occurrenceCount: "223"
pluginId: "10038"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "223"
wascId: "15"
---

# Content Security Policy (CSP) Header Not Set (Plugin 10038)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentSecurityPolicyMissingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentSecurityPolicyMissingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10038/

### How it detects

Passive; threshold: low

_threshold: low_

## Remediation

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### References
- https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
- https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- https://www.w3.org/TR/CSP/
- https://w3c.github.io/webappsec-csp/
- https://web.dev/articles/csp
- https://caniuse.com/#feat=contentsecuritypolicy
- https://content-security-policy.com/

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a54791cb65657570.md|Issue fin-a54791cb65657570]]
#### Observations
- [[occurrences/occ-8b66467bad929591.md|public-firing-range.appspot.com/]]

### GET https://public-firing-range.appspot.com/address/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e2c7c17541766585.md|Issue fin-e2c7c17541766585]]
#### Observations
- [[occurrences/occ-c845ddf7ddcdfe36.md|address]]

### GET https://public-firing-range.appspot.com/address/URL/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e29cff1e3aace724.md|Issue fin-e29cff1e3aace724]]
#### Observations
- [[occurrences/occ-1ac97411bc7332a8.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/URLUnencoded/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-495aa2f5d7defd9a.md|Issue fin-495aa2f5d7defd9a]]
#### Observations
- [[occurrences/occ-0584a7fdbee9790e.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/baseURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dbc719915457851b.md|Issue fin-dbc719915457851b]]
#### Observations
- [[occurrences/occ-dfc3f61338661e5f.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/documentURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-97b0329f3e5805f6.md|Issue fin-97b0329f3e5805f6]]
#### Observations
- [[occurrences/occ-27b57100ee8be84a.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d6f1865e94921762.md|Issue fin-d6f1865e94921762]]
#### Observations
- [[occurrences/occ-0806f3be59db87e4.md|address/index.html]]

### GET https://public-firing-range.appspot.com/address/location.hash/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a5b9195ed8970bf4.md|Issue fin-a5b9195ed8970bf4]]
#### Observations
- [[occurrences/occ-a4b537509b60f1a9.md|assign]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-96fa25631c4ec77e.md|Issue fin-96fa25631c4ec77e]]
#### Observations
- [[occurrences/occ-27dab295c33d5682.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-61ae49095ca93b4f.md|Issue fin-61ae49095ca93b4f]]
#### Observations
- [[occurrences/occ-09eab19fc70acd5b.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-40a2e5f6c69932c6.md|Issue fin-40a2e5f6c69932c6]]
#### Observations
- [[occurrences/occ-0a2955f6645781ce.md|eval]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-18c0c5b754364bd8.md|Issue fin-18c0c5b754364bd8]]
#### Observations
- [[occurrences/occ-836aca0ac080d5b1.md|formaction]]

### GET https://public-firing-range.appspot.com/address/location.hash/function  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e88f9c1d10181731.md|Issue fin-e88f9c1d10181731]]
#### Observations
- [[occurrences/occ-0cdef01548a9a5da.md|function]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-73807b9151d9f688.md|Issue fin-73807b9151d9f688]]
#### Observations
- [[occurrences/occ-32b088737ee69ad5.md|inlineevent]]

### GET https://public-firing-range.appspot.com/address/location.hash/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-14c58bfb3cb2e197.md|Issue fin-14c58bfb3cb2e197]]
#### Observations
- [[occurrences/occ-4012905bbc2d075f.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location.hash/jshref  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3df9868787452535.md|Issue fin-3df9868787452535]]
#### Observations
- [[occurrences/occ-7da6656a6cb6fbfa.md|jshref]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickAddEventListener  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fd48cb716f35a85a.md|Issue fin-fd48cb716f35a85a]]
#### Observations
- [[occurrences/occ-3ed988842a795424.md|onclickAddEventListener]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickSetAttribute  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-608f6b098f9b2935.md|Issue fin-608f6b098f9b2935]]
#### Observations
- [[occurrences/occ-41c38c0296c92ede.md|onclickSetAttribute]]

### GET https://public-firing-range.appspot.com/address/location.hash/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f30af34b7914deb8.md|Issue fin-f30af34b7914deb8]]
#### Observations
- [[occurrences/occ-7a91013ab2d8a6f0.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-607a1babf4911a30.md|Issue fin-607a1babf4911a30]]
#### Observations
- [[occurrences/occ-11e57cec5bfdc6d5.md|replace]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e3c988c42b52e190.md|Issue fin-e3c988c42b52e190]]
#### Observations
- [[occurrences/occ-5ee052f47b05494a.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/location/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-498ecdf0d485da5f.md|Issue fin-498ecdf0d485da5f]]
#### Observations
- [[occurrences/occ-e7c13caddf2d587e.md|assign]]

### GET https://public-firing-range.appspot.com/address/location/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c316cec02b64f2d0.md|Issue fin-c316cec02b64f2d0]]
#### Observations
- [[occurrences/occ-b7faae3edd3fa43b.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-97a9ff43a858d05d.md|Issue fin-97a9ff43a858d05d]]
#### Observations
- [[occurrences/occ-f9e3d25974c1ee16.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aacd3019e2882ff5.md|Issue fin-aacd3019e2882ff5]]
#### Observations
- [[occurrences/occ-30bbd6c9394b0298.md|eval]]

### GET https://public-firing-range.appspot.com/address/location/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-10ad74b7d67f0e13.md|Issue fin-10ad74b7d67f0e13]]
#### Observations
- [[occurrences/occ-b15ca323d532860c.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-57686d5c89aaedfc.md|Issue fin-57686d5c89aaedfc]]
#### Observations
- [[occurrences/occ-61dbf21d1179a748.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-589e000c696b94aa.md|Issue fin-589e000c696b94aa]]
#### Observations
- [[occurrences/occ-9c0836c0fc017d48.md|replace]]

### GET https://public-firing-range.appspot.com/address/location/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cfa5acf6a9e15cbe.md|Issue fin-cfa5acf6a9e15cbe]]
#### Observations
- [[occurrences/occ-eb391a9ce367d54b.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/locationhref/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a950b8d79af59312.md|Issue fin-a950b8d79af59312]]
#### Observations
- [[occurrences/occ-ba281e9a9a4ec270.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationpathname/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8786a018149a29fa.md|Issue fin-8786a018149a29fa]]
#### Observations
- [[occurrences/occ-cdb1d0c22d65ced5.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationsearch/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bac93789d43955c1.md|Issue fin-bac93789d43955c1]]
#### Observations
- [[occurrences/occ-6dce859b53a8d1a8.md|documentwrite]]

### GET https://public-firing-range.appspot.com/angular/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6711d39be1fa582e.md|Issue fin-6711d39be1fa582e]]
#### Observations
- [[occurrences/occ-dec01d6e04e3bf6b.md|angular]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-51eb53798c914089.md|Issue fin-51eb53798c914089]]
#### Observations
- [[occurrences/occ-6cbb5ce4d4d11334.md|1.1.5]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3afde16b33fcf11a.md|Issue fin-3afde16b33fcf11a]]
#### Observations
- [[occurrences/occ-5426a8a1b7c671c4.md|1.2.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a7cd4dbae9a03208.md|Issue fin-a7cd4dbae9a03208]]
#### Observations
- [[occurrences/occ-bbef1361f81a32f4.md|1.2.18]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-523580a4a710e9af.md|Issue fin-523580a4a710e9af]]
#### Observations
- [[occurrences/occ-4273feb8bdc0790d.md|1.2.19]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ac8dab43a8d05651.md|Issue fin-ac8dab43a8d05651]]
#### Observations
- [[occurrences/occ-3c1b7b72bf67ee20.md|1.2.24]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dcb05be7a66c2abe.md|Issue fin-dcb05be7a66c2abe]]
#### Observations
- [[occurrences/occ-ba9b471cdd936824.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ba17827ee8fb9ba.md|Issue fin-0ba17827ee8fb9ba]]
#### Observations
- [[occurrences/occ-2c002f4a54547578.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2a8501d96f1c2171.md|Issue fin-2a8501d96f1c2171]]
#### Observations
- [[occurrences/occ-97e2d1cb1bfeffde.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b245840438cec28c.md|Issue fin-b245840438cec28c]]
#### Observations
- [[occurrences/occ-7d69f4b1537ea8b5.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c8820efd6402be96.md|Issue fin-c8820efd6402be96]]
#### Observations
- [[occurrences/occ-9274c44e2ca8e225.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4318fef97655a1b4.md|Issue fin-4318fef97655a1b4]]
#### Observations
- [[occurrences/occ-12c335cf7932816b.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-518f5fe72356945b.md|Issue fin-518f5fe72356945b]]
#### Observations
- [[occurrences/occ-c33e5f7e57d40f44.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5ab85a88d32ea318.md|Issue fin-5ab85a88d32ea318]]
#### Observations
- [[occurrences/occ-4e75f01cf55dbf42.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d60c44a6ab51960c.md|Issue fin-d60c44a6ab51960c]]
#### Observations
- [[occurrences/occ-e83d8e84ac3a0ecc.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f34f0cf121a65727.md|Issue fin-f34f0cf121a65727]]
#### Observations
- [[occurrences/occ-1867dab0e33a9d0a.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-34a88b4ea2960c11.md|Issue fin-34a88b4ea2960c11]]
#### Observations
- [[occurrences/occ-ce141b02c76bd0c4.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5394806f5b8f6eb1.md|Issue fin-5394806f5b8f6eb1]]
#### Observations
- [[occurrences/occ-1f026bf3057f0130.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f01faa936525e337.md|Issue fin-f01faa936525e337]]
#### Observations
- [[occurrences/occ-76ebe66af95cf147.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-313dd70eface43d4.md|Issue fin-313dd70eface43d4]]
#### Observations
- [[occurrences/occ-f2caa6bcfd0320dd.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b5e9b19afa14b10d.md|Issue fin-b5e9b19afa14b10d]]
#### Observations
- [[occurrences/occ-cc7db37c8ea7630d.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-460b50985d64df6f.md|Issue fin-460b50985d64df6f]]
#### Observations
- [[occurrences/occ-7d51694f316fa3da.md|angular/index.html]]

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9edc5006e492fbaa.md|Issue fin-9edc5006e492fbaa]]
#### Observations
- [[occurrences/occ-7b1dded505c8ab32.md|badscriptimport]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dffab44a42edccdf.md|Issue fin-dffab44a42edccdf]]
#### Observations
- [[occurrences/occ-5521398460156a80.md|badscriptimport/index.html]]

### GET https://public-firing-range.appspot.com/clickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a536bd029c1dc50a.md|Issue fin-a536bd029c1dc50a]]
#### Observations
- [[occurrences/occ-9f6c3c0bc88a6377.md|clickjacking]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_xfo_allowall  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1445da454679e155.md|Issue fin-1445da454679e155]]
#### Observations
- [[occurrences/occ-00c2c3f2afdcb40f.md|clickjacking_xfo_allowall]]

### GET https://public-firing-range.appspot.com/clickjacking/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-81c15812750b8e93.md|Issue fin-81c15812750b8e93]]
#### Observations
- [[occurrences/occ-4b7ddd211c013ac0.md|clickjacking/index.html]]

### GET https://public-firing-range.appspot.com/cors/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1c4a72cd6a5b36c1.md|Issue fin-1c4a72cd6a5b36c1]]
#### Observations
- [[occurrences/occ-89bca4b232b0eacb.md|cors]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowInsecureScheme  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-86b8f9dcec98e369.md|Issue fin-86b8f9dcec98e369]]
#### Observations
- [[occurrences/occ-42a6e95b7240ddd5.md|allowInsecureScheme]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ecf8cda21ff4d9bf.md|Issue fin-ecf8cda21ff4d9bf]]
#### Observations
- [[occurrences/occ-a77be8e73a992148.md|allowNullOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f8f69ced76214bdc.md|Issue fin-f8f69ced76214bdc]]
#### Observations
- [[occurrences/occ-8c3c72f3cb7d524a.md|allowNullOrigin]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-99fd5ecfaf43d0fc.md|Issue fin-99fd5ecfaf43d0fc]]
#### Observations
- [[occurrences/occ-31231adb221557e1.md|allowOriginEndsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f1c6f8e1ed106cc5.md|Issue fin-f1c6f8e1ed106cc5]]
#### Observations
- [[occurrences/occ-b02fae296ec8f021.md|allowOriginEndsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginProtocolDowngrade  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-024fc7626852aff4.md|Issue fin-024fc7626852aff4]]
#### Observations
- [[occurrences/occ-7537c54a38b262c4.md|allowOriginProtocolDowngrade]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginRegexDot  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5dadffe8bee4039f.md|Issue fin-5dadffe8bee4039f]]
#### Observations
- [[occurrences/occ-00f40e71c38086c5.md|allowOriginRegexDot]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a424f7ede483bd36.md|Issue fin-a424f7ede483bd36]]
#### Observations
- [[occurrences/occ-2d24a12a5da6518a.md|allowOriginStartsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c23f4f542ac85f7d.md|Issue fin-c23f4f542ac85f7d]]
#### Observations
- [[occurrences/occ-dc3dba5bf8584145.md|allowOriginStartsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-15b52d895ea33133.md|Issue fin-15b52d895ea33133]]
#### Observations
- [[occurrences/occ-8535a22a140d6934.md|dynamicAllowOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1cdd5d203c7bf2c5.md|Issue fin-1cdd5d203c7bf2c5]]
#### Observations
- [[occurrences/occ-ee956fd492868979.md|dynamicAllowOrigin]]

### GET https://public-firing-range.appspot.com/cors/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-90d4d7c5fa173ba7.md|Issue fin-90d4d7c5fa173ba7]]
#### Observations
- [[occurrences/occ-d53e21c93495966d.md|cors/index.html]]

### GET https://public-firing-range.appspot.com/dom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e7ec22c3d433be8f.md|Issue fin-e7ec22c3d433be8f]]
#### Observations
- [[occurrences/occ-56163a0730acddb2.md|dom]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-56c75788f312af0b.md|Issue fin-56c75788f312af0b]]
#### Observations
- [[occurrences/occ-87ea42ad3b107171.md|dompropagation]]

### GET https://public-firing-range.appspot.com/dom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4c467f6656f0343c.md|Issue fin-4c467f6656f0343c]]
#### Observations
- [[occurrences/occ-83225f646bd133b9.md|dom/index.html]]

### GET https://public-firing-range.appspot.com/dom/javascripturi.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1046ab550ff05a91.md|Issue fin-1046ab550ff05a91]]
#### Observations
- [[occurrences/occ-39ea4e45cb1cf6f1.md|javascripturi.html]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-12fc48f7f24a8c82.md|Issue fin-12fc48f7f24a8c82]]
#### Observations
- [[occurrences/occ-1dd9853132b33531.md|complexMessageDocumentWriteEval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1643be823a294cad.md|Issue fin-1643be823a294cad]]
#### Observations
- [[occurrences/occ-6ca6037ba970901b.md|documentWrite]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-333547e6ca4e5b0f.md|Issue fin-333547e6ca4e5b0f]]
#### Observations
- [[occurrences/occ-a54dd320f08bd18c.md|eval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-79e316fc70098b9b.md|Issue fin-79e316fc70098b9b]]
#### Observations
- [[occurrences/occ-9d730e534fb72651.md|improperOriginValid…tialStringComparison]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-36692fbab72a8f38.md|Issue fin-36692fbab72a8f38]]
#### Observations
- [[occurrences/occ-39befe81d7cb110c.md|improperOriginValidationWithRegExp]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-22e644da23e37d5b.md|Issue fin-22e644da23e37d5b]]
#### Observations
- [[occurrences/occ-c975c05b9c21e005.md|innerHtml]]

### GET https://public-firing-range.appspot.com/escape/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e834d51ae4eece61.md|Issue fin-e834d51ae4eece61]]
#### Observations
- [[occurrences/occ-c2a898527e6aed7e.md|escape]]

### GET https://public-firing-range.appspot.com/escape/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e985ccf764930f85.md|Issue fin-e985ccf764930f85]]
#### Observations
- [[occurrences/occ-1e1497480d8d1d83.md|escape/index.html]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4287642c63479bb4.md|Issue fin-4287642c63479bb4]]
#### Observations
- [[occurrences/occ-8d87d65e84510aa5.md|encodeURIComponent]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3a32b061e3c0cdff.md|Issue fin-3a32b061e3c0cdff]]
#### Observations
- [[occurrences/occ-8d2e7e3bb2967f24.md|escape]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9f6b53683314a439.md|Issue fin-9f6b53683314a439]]
#### Observations
- [[occurrences/occ-9bd8321dc7b357c0.md|html_escape]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ceaeb7a152ab3e57.md|Issue fin-ceaeb7a152ab3e57]]
#### Observations
- [[occurrences/occ-73832fbdbb6da043.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c32c9e72ce5a954e.md|Issue fin-c32c9e72ce5a954e]]
#### Observations
- [[occurrences/occ-35cc8f6ed735638c.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0a534aac87b2ab0c.md|Issue fin-0a534aac87b2ab0c]]
#### Observations
- [[occurrences/occ-d45805a3d0bdab44.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-73581ff1f674e9d9.md|Issue fin-73581ff1f674e9d9]]
#### Observations
- [[occurrences/occ-9586c5bb4be6f712.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de26393a3b4a310b.md|Issue fin-de26393a3b4a310b]]
#### Observations
- [[occurrences/occ-cdc10f2aab073cf1.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-80489489c6838633.md|Issue fin-80489489c6838633]]
#### Observations
- [[occurrences/occ-6a6427f7371b6e86.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-face47ea27d5df3f.md|Issue fin-face47ea27d5df3f]]
#### Observations
- [[occurrences/occ-4c3df7eb93dbef12.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c1961a85887bf671.md|Issue fin-c1961a85887bf671]]
#### Observations
- [[occurrences/occ-a73c561c6f46c987.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f34627a5a504323a.md|Issue fin-f34627a5a504323a]]
#### Observations
- [[occurrences/occ-0f08ac6c913391ab.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee6df343a2e1a22a.md|Issue fin-ee6df343a2e1a22a]]
#### Observations
- [[occurrences/occ-42a72658b054f39d.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-213c5be03093215a.md|Issue fin-213c5be03093215a]]
#### Observations
- [[occurrences/occ-6a449b98ca359c3d.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a1139fdec48da5ff.md|Issue fin-a1139fdec48da5ff]]
#### Observations
- [[occurrences/occ-bb94d651e48f6632.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a05459b07d505593.md|Issue fin-a05459b07d505593]]
#### Observations
- [[occurrences/occ-2c1619e7c13d63fc.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-34d733355503ebf0.md|Issue fin-34d733355503ebf0]]
#### Observations
- [[occurrences/occ-54fcdb24db55c6fd.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-07d7d84f74e5416d.md|Issue fin-07d7d84f74e5416d]]
#### Observations
- [[occurrences/occ-92534589c40a81dc.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-756c3906ab5f9436.md|Issue fin-756c3906ab5f9436]]
#### Observations
- [[occurrences/occ-ff27afa21981940e.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-38a7d3f74b3d5d2d.md|Issue fin-38a7d3f74b3d5d2d]]
#### Observations
- [[occurrences/occ-2f7326a3b28fdc55.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-25ae64f2fed3a6bc.md|Issue fin-25ae64f2fed3a6bc]]
#### Observations
- [[occurrences/occ-ba9615a634fe4c51.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f402e7e867b2d9bd.md|Issue fin-f402e7e867b2d9bd]]
#### Observations
- [[occurrences/occ-433d260fe2f1a445.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-06bbab997d1515c9.md|Issue fin-06bbab997d1515c9]]
#### Observations
- [[occurrences/occ-010e729164a3c403.md|textarea]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bece9779c81f31d0.md|Issue fin-bece9779c81f31d0]]
#### Observations
- [[occurrences/occ-037d68895b3a05c0.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2b5916f191f1108c.md|Issue fin-2b5916f191f1108c]]
#### Observations
- [[occurrences/occ-5ed45ddc67e181df.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e578ed414461e40c.md|Issue fin-e578ed414461e40c]]
#### Observations
- [[occurrences/occ-4f00be22b605371c.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e8ef1c70825dd3fe.md|Issue fin-e8ef1c70825dd3fe]]
#### Observations
- [[occurrences/occ-ca1a6916e28db1c6.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-65fcf8adcd0595bf.md|Issue fin-65fcf8adcd0595bf]]
#### Observations
- [[occurrences/occ-5efbb3d95483a41e.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3100ed74b2caf1f8.md|Issue fin-3100ed74b2caf1f8]]
#### Observations
- [[occurrences/occ-f4c2737dec3f4ac3.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7ad6355c516b6e53.md|Issue fin-7ad6355c516b6e53]]
#### Observations
- [[occurrences/occ-cebd255a3c7d7992.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0914025382276463.md|Issue fin-0914025382276463]]
#### Observations
- [[occurrences/occ-368ed38ea991052d.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dcbff5c02ce9958c.md|Issue fin-dcbff5c02ce9958c]]
#### Observations
- [[occurrences/occ-0402d035deb833f7.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9b73e57d482c7857.md|Issue fin-9b73e57d482c7857]]
#### Observations
- [[occurrences/occ-3645a61c991343bf.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_value?q=a&escape=HTML_ESCAPE  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bd59fe4e026b08a2.md|Issue fin-bd59fe4e026b08a2]]
#### Observations
- [[occurrences/occ-a5bdb6d9001c190a.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-73e3b4ad05dc8216.md|Issue fin-73e3b4ad05dc8216]]
#### Observations
- [[occurrences/occ-bc2bcc107ad768ad.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2b287d6ce11ad334.md|Issue fin-2b287d6ce11ad334]]
#### Observations
- [[occurrences/occ-6db8ce29ca2680b3.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f233668448358bd4.md|Issue fin-f233668448358bd4]]
#### Observations
- [[occurrences/occ-3df3c72f55a0c700.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de8da55489e72367.md|Issue fin-de8da55489e72367]]
#### Observations
- [[occurrences/occ-720188bed505cdd5.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ff57c1def452208b.md|Issue fin-ff57c1def452208b]]
#### Observations
- [[occurrences/occ-761643f37d156832.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f3635e29508994dd.md|Issue fin-f3635e29508994dd]]
#### Observations
- [[occurrences/occ-111fd3f9673ca871.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-651f0ce48072baeb.md|Issue fin-651f0ce48072baeb]]
#### Observations
- [[occurrences/occ-4f699940bfeaf22b.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f481cdf9d2c5f0b2.md|Issue fin-f481cdf9d2c5f0b2]]
#### Observations
- [[occurrences/occ-b14d1d9a1733d34d.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1aba724c00e93fac.md|Issue fin-1aba724c00e93fac]]
#### Observations
- [[occurrences/occ-6c0697444117caa2.md|textarea]]

### GET https://public-firing-range.appspot.com/favicon.ico  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-75963be5b852bcf4.md|Issue fin-75963be5b852bcf4]]
#### Observations
- [[occurrences/occ-d310dfd66a0bf0fb.md|favicon.ico]]

### GET https://public-firing-range.appspot.com/flashinjection/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d4daf8660271a5c2.md|Issue fin-d4daf8660271a5c2]]
#### Observations
- [[occurrences/occ-acf672eda1fc7e13.md|flashinjection]]

### GET https://public-firing-range.appspot.com/flashinjection/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0961a115ef1eff4b.md|Issue fin-0961a115ef1eff4b]]
#### Observations
- [[occurrences/occ-048340e49c16b8b9.md|flashinjection/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ea9762a1c8ca6fde.md|Issue fin-ea9762a1c8ca6fde]]
#### Observations
- [[occurrences/occ-acaec1d9d822fae6.md|insecurethirdpartyscripts]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-448491171bb3cad4.md|Issue fin-448491171bb3cad4]]
#### Observations
- [[occurrences/occ-efb0250f784c027b.md|insecurethirdpartyscripts/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7228036b1b5fcc9c.md|Issue fin-7228036b1b5fcc9c]]
#### Observations
- [[occurrences/occ-fe296790d5415792.md|third_party_scripts…ource_integrity.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ca4e8f743f1ac161.md|Issue fin-ca4e8f743f1ac161]]
#### Observations
- [[occurrences/occ-0102bb2012584a79.md|third_party_scripts…namically_added.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-30f8e279ddd56b70.md|Issue fin-30f8e279ddd56b70]]
#### Observations
- [[occurrences/occ-a4f8d8ca664a76c6.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0f1ffb5ad198f8bb.md|Issue fin-0f1ffb5ad198f8bb]]
#### Observations
- [[occurrences/occ-e250efab75ade306.md|leakedcookie/index.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-deb8a5624ba21edf.md|Issue fin-deb8a5624ba21edf]]
#### Observations
- [[occurrences/occ-c260e5b31d9797ce.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-06bb1eb6dd0ea36c.md|Issue fin-06bb1eb6dd0ea36c]]
#### Observations
- [[occurrences/occ-9f1af737e6548eae.md|leakedinresource]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-25c2eb698e305812.md|Issue fin-25c2eb698e305812]]
#### Observations
- [[occurrences/occ-af184e0d3d9cb411.md|mixedcontent]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2648f24d63b745a0.md|Issue fin-2648f24d63b745a0]]
#### Observations
- [[occurrences/occ-dce292a95d5d04ca.md|mixedcontent/index.html]]

### GET https://public-firing-range.appspot.com/redirect/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-49d7f024c285b010.md|Issue fin-49d7f024c285b010]]
#### Observations
- [[occurrences/occ-330e85997195b0c2.md|redirect]]

### GET https://public-firing-range.appspot.com/redirect/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fda0990b10b9b5b2.md|Issue fin-fda0990b10b9b5b2]]
#### Observations
- [[occurrences/occ-c651284b17307c2f.md|redirect/index.html]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ba930798068858d0.md|Issue fin-ba930798068858d0]]
#### Observations
- [[occurrences/occ-c0215b69a6fb1439.md|meta]]

### GET https://public-firing-range.appspot.com/reflected/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-31f8675691fd095b.md|Issue fin-31f8675691fd095b]]
#### Observations
- [[occurrences/occ-ae04cd2db5d057f2.md|reflected]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d59e73068be1f338.md|Issue fin-d59e73068be1f338]]
#### Observations
- [[occurrences/occ-2b64213d05bf951c.md|DOUBLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-635212e980b2ea3a.md|Issue fin-635212e980b2ea3a]]
#### Observations
- [[occurrences/occ-4c48ceb69dcc8a18.md|SINGLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-04494a58cc2ef89d.md|Issue fin-04494a58cc2ef89d]]
#### Observations
- [[occurrences/occ-ad30746b22b33445.md|UNQUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b264d154bee5b111.md|Issue fin-b264d154bee5b111]]
#### Observations
- [[occurrences/occ-9b5928448c69156a.md|DoubleQuoteSinglequote]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce7ba7d21dba6668.md|Issue fin-ce7ba7d21dba6668]]
#### Observations
- [[occurrences/occ-bdfb0d35af18fd64.md|SpaceDoubleQuoteSlashEquals]]

### GET https://public-firing-range.appspot.com/reflected/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e07a7061d2821c23.md|Issue fin-e07a7061d2821c23]]
#### Observations
- [[occurrences/occ-e9c529fac9a6da43.md|reflected/index.html]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cbef8f1ab47b99a8.md|Issue fin-cbef8f1ab47b99a8]]
#### Observations
- [[occurrences/occ-abb5200980c86680.md|attribute_name]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e6dedc6c1e915921.md|Issue fin-e6dedc6c1e915921]]
#### Observations
- [[occurrences/occ-625121d99ba31fc7.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f3ea2df7dfb0d0c9.md|Issue fin-f3ea2df7dfb0d0c9]]
#### Observations
- [[occurrences/occ-bd909aa966eeec11.md|attribute_script]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f6d19fed4f86473f.md|Issue fin-f6d19fed4f86473f]]
#### Observations
- [[occurrences/occ-99bbe830995adad5.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fafb2915600cd8ef.md|Issue fin-fafb2915600cd8ef]]
#### Observations
- [[occurrences/occ-410768b1119d7828.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/400?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e7f5dcb9c6280c93.md|Issue fin-e7f5dcb9c6280c93]]
#### Observations
- [[occurrences/occ-4835c53a928c7af0.md|400]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/401?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-63bc30dbae7c0dab.md|Issue fin-63bc30dbae7c0dab]]
#### Observations
- [[occurrences/occ-c8f9bb4329bce485.md|401]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/403?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a08c1ed19da87deb.md|Issue fin-a08c1ed19da87deb]]
#### Observations
- [[occurrences/occ-ff4e0ae35c9b5dc1.md|403]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/404?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-77c5f635967836ec.md|Issue fin-77c5f635967836ec]]
#### Observations
- [[occurrences/occ-565f123d973c2ae1.md|404]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/500?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d4e7d0081c8e6f58.md|Issue fin-d4e7d0081c8e6f58]]
#### Observations
- [[occurrences/occ-de678d862da011f6.md|500]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0bc6b4c1a39f5e99.md|Issue fin-0bc6b4c1a39f5e99]]
#### Observations
- [[occurrences/occ-3ce44be470046d84.md|body]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-06d266f645dd524a.md|Issue fin-06d266f645dd524a]]
#### Observations
- [[occurrences/occ-8c9c1974152b56e0.md|body_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8e98eda90f0898fc.md|Issue fin-8e98eda90f0898fc]]
#### Observations
- [[occurrences/occ-8bedd9e1e79b1f66.md|css_style]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0d78dd1bb8ffc018.md|Issue fin-0d78dd1bb8ffc018]]
#### Observations
- [[occurrences/occ-8a6a00624ae3bef2.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9c28a397d0e89dae.md|Issue fin-9c28a397d0e89dae]]
#### Observations
- [[occurrences/occ-0cff0eea879e9685.md|css_style_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/form  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-702d397977d23508.md|Issue fin-702d397977d23508]]
#### Observations
- [[occurrences/occ-931e8dd7211dd59e.md|form]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0b6ac150e75ca87a.md|Issue fin-0b6ac150e75ca87a]]
#### Observations
- [[occurrences/occ-c53ce7a64c468226.md|head]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-65f4a19fafced8aa.md|Issue fin-65f4a19fafced8aa]]
#### Observations
- [[occurrences/occ-e40f5f702bbc6663.md|iframe_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ac737773ec84fb30.md|Issue fin-ac737773ec84fb30]]
#### Observations
- [[occurrences/occ-fdfc8ee2077a7006.md|iframe_srcdoc]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cf3a41f441f7888b.md|Issue fin-cf3a41f441f7888b]]
#### Observations
- [[occurrences/occ-84324dd23dd25bdb.md|js_assignment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-87019c8618ec8ee4.md|Issue fin-87019c8618ec8ee4]]
#### Observations
- [[occurrences/occ-627a96a6260e28ca.md|js_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce4c3a7b5f129d73.md|Issue fin-ce4c3a7b5f129d73]]
#### Observations
- [[occurrences/occ-c12a9644fb12c166.md|js_eval]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-614ce77a6d146d9e.md|Issue fin-614ce77a6d146d9e]]
#### Observations
- [[occurrences/occ-34f86b80172a96d6.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-376789a7c1f6446a.md|Issue fin-376789a7c1f6446a]]
#### Observations
- [[occurrences/occ-4b117b0163aeb10c.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-32c6c2d3fe2b7c91.md|Issue fin-32c6c2d3fe2b7c91]]
#### Observations
- [[occurrences/occ-fe2044c3382264aa.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-18fa29d8469570bc.md|Issue fin-18fa29d8469570bc]]
#### Observations
- [[occurrences/occ-86b536aac3301e07.md|json]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-64d4e96025ad2d61.md|Issue fin-64d4e96025ad2d61]]
#### Observations
- [[occurrences/occ-694ec952a7e7113d.md|noscript]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a07883c0862bf005.md|Issue fin-a07883c0862bf005]]
#### Observations
- [[occurrences/occ-6adadd40c4db13eb.md|style_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-513e27733adcda9e.md|Issue fin-513e27733adcda9e]]
#### Observations
- [[occurrences/occ-d3fd89d692dd4b4d.md|tagname]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-830f4ebeacd4914b.md|Issue fin-830f4ebeacd4914b]]
#### Observations
- [[occurrences/occ-c2296130b0a3e430.md|textarea]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ea12800e0ca74c73.md|Issue fin-ea12800e0ca74c73]]
#### Observations
- [[occurrences/occ-8d7c63b04122bb30.md|textarea_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aff2d194497bf3b2.md|Issue fin-aff2d194497bf3b2]]
#### Observations
- [[occurrences/occ-8c81830fd8e1207e.md|title]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cc098c9733a11637.md|Issue fin-cc098c9733a11637]]
#### Observations
- [[occurrences/occ-1d42bbd401d96097.md|css_import]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9846f0fa7118a184.md|Issue fin-9846f0fa7118a184]]
#### Observations
- [[occurrences/occ-92e65574a7bd6743.md|href]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-22406717f2329f46.md|Issue fin-22406717f2329f46]]
#### Observations
- [[occurrences/occ-f72ec2bf9804eaf1.md|object_data]]

### GET https://public-firing-range.appspot.com/reflected/url/object_param?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c1f240a606a899af.md|Issue fin-c1f240a606a899af]]
#### Observations
- [[occurrences/occ-4af7bb223cd4e523.md|object_param]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-82917d34081a9a94.md|Issue fin-82917d34081a9a94]]
#### Observations
- [[occurrences/occ-a608484567781c16.md|script_src]]

### GET https://public-firing-range.appspot.com/remoteinclude/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2ecde4002cbb2de0.md|Issue fin-2ecde4002cbb2de0]]
#### Observations
- [[occurrences/occ-ba9b4c8d480f5d5a.md|remoteinclude]]

### GET https://public-firing-range.appspot.com/remoteinclude/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-046d5b3e4c23ff45.md|Issue fin-046d5b3e4c23ff45]]
#### Observations
- [[occurrences/occ-042a4ab946ba5bb0.md|remoteinclude/index.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d7c2a64995ddee7d.md|Issue fin-d7c2a64995ddee7d]]
#### Observations
- [[occurrences/occ-3736aa3bbf864e0a.md|object_hash.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5aec2231344e162b.md|Issue fin-5aec2231344e162b]]
#### Observations
- [[occurrences/occ-d24fb706f2421aa1.md|application_x-shockwave-flash]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cf885d9ef6eeca68.md|Issue fin-cf885d9ef6eeca68]]
#### Observations
- [[occurrences/occ-41c1e706432204f2.md|object_raw]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c7a8d1f2407d8df7.md|Issue fin-c7a8d1f2407d8df7]]
#### Observations
- [[occurrences/occ-4a8e9c2e40ded118.md|script]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-166d47185025d066.md|Issue fin-166d47185025d066]]
#### Observations
- [[occurrences/occ-1a8a5ae7121bec3c.md|script_hash.html]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5b5746da0f25679d.md|Issue fin-5b5746da0f25679d]]
#### Observations
- [[occurrences/occ-06218ac63af794ef.md|reverseclickjacking]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2feeed759f8289f9.md|Issue fin-2feeed759f8289f9]]
#### Observations
- [[occurrences/occ-9a8a0f2e55a120b2.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4cfa5a018cf85359.md|Issue fin-4cfa5a018cf85359]]
#### Observations
- [[occurrences/occ-72235d0777910522.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6140d9e71997f393.md|Issue fin-6140d9e71997f393]]
#### Observations
- [[occurrences/occ-0a173b0e9117fe77.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-40a51afb358cad87.md|Issue fin-40a51afb358cad87]]
#### Observations
- [[occurrences/occ-71581c0949c81219.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2c9f1ad1daf5a22c.md|Issue fin-2c9f1ad1daf5a22c]]
#### Observations
- [[occurrences/occ-402ad3b8cd8b73e7.md|stricttransportsecurity]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_includesubdomains_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee814694d5de3ba1.md|Issue fin-ee814694d5de3ba1]]
#### Observations
- [[occurrences/occ-ce9fb84e38ea6faf.md|hsts_includesubdomains_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d7a6592aa5b111ff.md|Issue fin-d7a6592aa5b111ff]]
#### Observations
- [[occurrences/occ-7cae74c829589c2f.md|hsts_max_age_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_too_low  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-132e7533990a5a05.md|Issue fin-132e7533990a5a05]]
#### Observations
- [[occurrences/occ-075327f519ec99de.md|hsts_max_age_too_low]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d78afe30b7fba599.md|Issue fin-d78afe30b7fba599]]
#### Observations
- [[occurrences/occ-628a9721acdd179b.md|hsts_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_preload_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec8103868940ea2e.md|Issue fin-ec8103868940ea2e]]
#### Observations
- [[occurrences/occ-47d24dd30db0054b.md|hsts_preload_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ea058a2d796af158.md|Issue fin-ea058a2d796af158]]
#### Observations
- [[occurrences/occ-377c53c0240ad1fc.md|stricttransportsecurity/index.html]]

### GET https://public-firing-range.appspot.com/tags/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-655ec4bc1e788d97.md|Issue fin-655ec4bc1e788d97]]
#### Observations
- [[occurrences/occ-6ca2cf0387721bd5.md|tags]]

### GET https://public-firing-range.appspot.com/tags/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-512fbe745d6ae8f3.md|Issue fin-512fbe745d6ae8f3]]
#### Observations
- [[occurrences/occ-3567e4522d7c3539.md|tags/index.html]]

### GET https://public-firing-range.appspot.com/tags/multiline?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f54bb2ab1f544685.md|Issue fin-f54bb2ab1f544685]]
#### Observations
- [[occurrences/occ-fc706f6528200fa3.md|multiline]]

### GET https://public-firing-range.appspot.com/urldom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7de44200dc1793a6.md|Issue fin-7de44200dc1793a6]]
#### Observations
- [[occurrences/occ-a5d838cdbfa178c4.md|urldom]]

### GET https://public-firing-range.appspot.com/urldom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-16a9257d54b5ed83.md|Issue fin-16a9257d54b5ed83]]
#### Observations
- [[occurrences/occ-13729218dba40f6b.md|urldom/index.html]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_domain  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5b3fe4be106ea307.md|Issue fin-5b3fe4be106ea307]]
#### Observations
- [[occurrences/occ-294ac46bf2ea475b.md|script.src.partial_domain]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_query  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-863b2bef43e1224b.md|Issue fin-863b2bef43e1224b]]
#### Observations
- [[occurrences/occ-163b145ba7348ad3.md|script.src.partial_query]]

### GET https://public-firing-range.appspot.com/urldom/location/search/area.href?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d79158fed01e87b5.md|Issue fin-d79158fed01e87b5]]
#### Observations
- [[occurrences/occ-bd6346e7653f70aa.md|area.href]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8451404b1d061ab0.md|Issue fin-8451404b1d061ab0]]
#### Observations
- [[occurrences/occ-721a95dbb6eaaaad.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b7c1eaf1c7441096.md|Issue fin-b7c1eaf1c7441096]]
#### Observations
- [[occurrences/occ-e9987502965e5094.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/frame.src?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c05e5c5e681b241f.md|Issue fin-c05e5c5e681b241f]]
#### Observations
- [[occurrences/occ-c60d74657b2dec2c.md|frame.src]]

### GET https://public-firing-range.appspot.com/urldom/location/search/location.assign?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-31f9e47820e638d4.md|Issue fin-31f9e47820e638d4]]
#### Observations
- [[occurrences/occ-9626a9087ec30cf3.md|location.assign]]

### GET https://public-firing-range.appspot.com/urldom/location/search/svg.a?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a5d5317600529d58.md|Issue fin-a5d5317600529d58]]
#### Observations
- [[occurrences/occ-5585fe814a9638a6.md|svg.a]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-35657fb9f5cc2cd8.md|Issue fin-35657fb9f5cc2cd8]]
#### Observations
- [[occurrences/occ-fa96581be897cbc8.md|vulnerablelibraries]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-946f2e249ae8ec34.md|Issue fin-946f2e249ae8ec34]]
#### Observations
- [[occurrences/occ-1f6a1de817ab32eb.md|vulnerablelibraries/index.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f02fbf37317cc8d.md|Issue fin-7f02fbf37317cc8d]]
#### Observations
- [[occurrences/occ-e3355a4b2f8e8959.md|jquery.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/x  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3d12be034637ba44.md|Issue fin-3d12be034637ba44]]
#### Observations
- [[occurrences/occ-bf7136ae0772b49c.md|x]]

