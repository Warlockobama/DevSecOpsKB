---
aliases:
  - "PP-0063"
cweId: "693"
cweUri: "https://cwe.mitre.org/data/definitions/693.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10063"
name: "Permissions Policy Header Not Set"
occurrenceCount: "225"
pluginId: "10063"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "225"
wascId: "15"
---

# Permissions Policy Header Not Set (Plugin 10063)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/PermissionsPolicyScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/PermissionsPolicyScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10063/

### How it detects

Passive; sets evidence; threshold: low

_threshold: low_

## Remediation

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header.

### References
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
- https://developer.chrome.com/blog/feature-policy/
- https://scotthelme.co.uk/a-new-security-header-feature-policy/
- https://w3c.github.io/webappsec-feature-policy/
- https://www.smashingmagazine.com/2018/12/feature-policy/

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0bff47806564877a.md|Issue fin-0bff47806564877a]]
#### Observations
- [[occurrences/occ-b311a412c75a11f8.md|public-firing-range.appspot.com/]]

### GET https://public-firing-range.appspot.com/address/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1568197b89be109c.md|Issue fin-1568197b89be109c]]
#### Observations
- [[occurrences/occ-61239eccb47e3e5b.md|address]]

### GET https://public-firing-range.appspot.com/address/URL/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-567f07b1c3340a7d.md|Issue fin-567f07b1c3340a7d]]
#### Observations
- [[occurrences/occ-bdc6260e3d4c1f32.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/URLUnencoded/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0f59a150d1a88d1a.md|Issue fin-0f59a150d1a88d1a]]
#### Observations
- [[occurrences/occ-e3ccf6bac0509315.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/baseURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e6f8ee01344a043d.md|Issue fin-e6f8ee01344a043d]]
#### Observations
- [[occurrences/occ-676baac349acd2c9.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/documentURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f7a1243a4a0f5d85.md|Issue fin-f7a1243a4a0f5d85]]
#### Observations
- [[occurrences/occ-0965a63f3da3d8bb.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-097b66ab35a6789a.md|Issue fin-097b66ab35a6789a]]
#### Observations
- [[occurrences/occ-2da2d3c012d8fa59.md|address/index.html]]

### GET https://public-firing-range.appspot.com/address/location.hash/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5bf0fe4443d9d60a.md|Issue fin-5bf0fe4443d9d60a]]
#### Observations
- [[occurrences/occ-ecf9b60dc72ba07f.md|assign]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2dfffefcd4f7a214.md|Issue fin-2dfffefcd4f7a214]]
#### Observations
- [[occurrences/occ-bfb32fb7e2b558d5.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-be05a77d3d37b1a0.md|Issue fin-be05a77d3d37b1a0]]
#### Observations
- [[occurrences/occ-2b7b66a68ccc52b3.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-29022cfc9ce6c45a.md|Issue fin-29022cfc9ce6c45a]]
#### Observations
- [[occurrences/occ-e89265fe85467557.md|eval]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a3a8a883d8647ece.md|Issue fin-a3a8a883d8647ece]]
#### Observations
- [[occurrences/occ-d74e3093c8834ab1.md|formaction]]

### GET https://public-firing-range.appspot.com/address/location.hash/function  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9c1d398938e34b7d.md|Issue fin-9c1d398938e34b7d]]
#### Observations
- [[occurrences/occ-add424eeea337ada.md|function]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1f6171a04012e3ff.md|Issue fin-1f6171a04012e3ff]]
#### Observations
- [[occurrences/occ-086bb10a31548969.md|inlineevent]]

### GET https://public-firing-range.appspot.com/address/location.hash/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c945ebb06fddb00b.md|Issue fin-c945ebb06fddb00b]]
#### Observations
- [[occurrences/occ-8be8f7d38d9d03b9.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location.hash/jshref  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-be7e0a0dcbb63aab.md|Issue fin-be7e0a0dcbb63aab]]
#### Observations
- [[occurrences/occ-d6932fdd5bca34c3.md|jshref]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickAddEventListener  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a4222612e1e43052.md|Issue fin-a4222612e1e43052]]
#### Observations
- [[occurrences/occ-24b9751fc4fe52b6.md|onclickAddEventListener]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickSetAttribute  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f57261c741a0ce13.md|Issue fin-f57261c741a0ce13]]
#### Observations
- [[occurrences/occ-ec4d97911a0594c6.md|onclickSetAttribute]]

### GET https://public-firing-range.appspot.com/address/location.hash/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de39efc1c04e5b62.md|Issue fin-de39efc1c04e5b62]]
#### Observations
- [[occurrences/occ-208b47b8fcc19d99.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cd52cd55ec0e98cb.md|Issue fin-cd52cd55ec0e98cb]]
#### Observations
- [[occurrences/occ-815d11e6375e4842.md|replace]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-669021e90c6992ee.md|Issue fin-669021e90c6992ee]]
#### Observations
- [[occurrences/occ-e7a3e58a8b677569.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/location/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6342632bdc2966b6.md|Issue fin-6342632bdc2966b6]]
#### Observations
- [[occurrences/occ-10afd29c97ce6463.md|assign]]

### GET https://public-firing-range.appspot.com/address/location/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2bdf48093b5be8da.md|Issue fin-2bdf48093b5be8da]]
#### Observations
- [[occurrences/occ-1b1461f4e5db17ae.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b158e0d9afb8e021.md|Issue fin-b158e0d9afb8e021]]
#### Observations
- [[occurrences/occ-937aaf1da3857035.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d35ed1d66ddea392.md|Issue fin-d35ed1d66ddea392]]
#### Observations
- [[occurrences/occ-6e82e9d398cfc688.md|eval]]

### GET https://public-firing-range.appspot.com/address/location/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c5310e198e2773c.md|Issue fin-0c5310e198e2773c]]
#### Observations
- [[occurrences/occ-c35c900aadbb35e8.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9ff4b8b522debea4.md|Issue fin-9ff4b8b522debea4]]
#### Observations
- [[occurrences/occ-3d1f8191522c8aa2.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e6a1941def2a2200.md|Issue fin-e6a1941def2a2200]]
#### Observations
- [[occurrences/occ-6e4f099202d535ae.md|replace]]

### GET https://public-firing-range.appspot.com/address/location/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c7fa7fabc7aacfd0.md|Issue fin-c7fa7fabc7aacfd0]]
#### Observations
- [[occurrences/occ-c9082ea6a14f35d6.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/locationhref/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-73d2f33490fcb6de.md|Issue fin-73d2f33490fcb6de]]
#### Observations
- [[occurrences/occ-02668ab13574c31c.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationpathname/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f9dc1c5ec3e2b29.md|Issue fin-7f9dc1c5ec3e2b29]]
#### Observations
- [[occurrences/occ-ec69debe81e7031d.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationsearch/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-90927f73539fa2e1.md|Issue fin-90927f73539fa2e1]]
#### Observations
- [[occurrences/occ-42525b52dce4e911.md|documentwrite]]

### GET https://public-firing-range.appspot.com/angular/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0e7e186ae9666626.md|Issue fin-0e7e186ae9666626]]
#### Observations
- [[occurrences/occ-3554a05c2a886462.md|angular]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a711cf5b95a38124.md|Issue fin-a711cf5b95a38124]]
#### Observations
- [[occurrences/occ-d9f41fd42d8afe56.md|1.1.5]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a7804d2c3a55630d.md|Issue fin-a7804d2c3a55630d]]
#### Observations
- [[occurrences/occ-5d0082ba9090fbea.md|1.2.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-305ccbf53c5e3252.md|Issue fin-305ccbf53c5e3252]]
#### Observations
- [[occurrences/occ-af5d0975799d75c8.md|1.2.18]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8815960fa018079c.md|Issue fin-8815960fa018079c]]
#### Observations
- [[occurrences/occ-c20124ae7b64b362.md|1.2.19]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b2ce247649997dda.md|Issue fin-b2ce247649997dda]]
#### Observations
- [[occurrences/occ-31745ea695b364d5.md|1.2.24]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6f6fece0820f7b98.md|Issue fin-6f6fece0820f7b98]]
#### Observations
- [[occurrences/occ-c9cd9d46d806217f.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5d6f17abcd10b7cd.md|Issue fin-5d6f17abcd10b7cd]]
#### Observations
- [[occurrences/occ-270c6ad5bb8132bf.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6cd5fde800209826.md|Issue fin-6cd5fde800209826]]
#### Observations
- [[occurrences/occ-cd1e71e6f563759e.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-064d7e056f6f1e79.md|Issue fin-064d7e056f6f1e79]]
#### Observations
- [[occurrences/occ-05d4141d1dc496dd.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b6a5236b83976240.md|Issue fin-b6a5236b83976240]]
#### Observations
- [[occurrences/occ-8cf19b79633c758f.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ba8af619c8b4b727.md|Issue fin-ba8af619c8b4b727]]
#### Observations
- [[occurrences/occ-6d8cb6f1d39bdbb3.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b51bd7e87c5f1dc1.md|Issue fin-b51bd7e87c5f1dc1]]
#### Observations
- [[occurrences/occ-df8f9a3fde2dabec.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c0c3964b14ffaa00.md|Issue fin-c0c3964b14ffaa00]]
#### Observations
- [[occurrences/occ-202a7e3e7231289d.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a49f7837dbe40402.md|Issue fin-a49f7837dbe40402]]
#### Observations
- [[occurrences/occ-d7b0667776da9d34.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ea577690b04278f3.md|Issue fin-ea577690b04278f3]]
#### Observations
- [[occurrences/occ-5781ca1d6957b933.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-69a38efca1bfa9cb.md|Issue fin-69a38efca1bfa9cb]]
#### Observations
- [[occurrences/occ-874b9dbff0dcd69a.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2e597e75509bc72f.md|Issue fin-2e597e75509bc72f]]
#### Observations
- [[occurrences/occ-9958df24bdce1010.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c057ef6686014fdb.md|Issue fin-c057ef6686014fdb]]
#### Observations
- [[occurrences/occ-4a3ecb6256420dc8.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-19bbe612bc8d9100.md|Issue fin-19bbe612bc8d9100]]
#### Observations
- [[occurrences/occ-d7b65d8a7e856843.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-797e259378509a59.md|Issue fin-797e259378509a59]]
#### Observations
- [[occurrences/occ-0ec4e1e3d2d20631.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6f7214d15d14b0b9.md|Issue fin-6f7214d15d14b0b9]]
#### Observations
- [[occurrences/occ-0cc9cae8493fe5f2.md|angular/index.html]]

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-489b3b6614c59d6c.md|Issue fin-489b3b6614c59d6c]]
#### Observations
- [[occurrences/occ-c1bc7e1a16e558f3.md|badscriptimport]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d109000ce2f124a7.md|Issue fin-d109000ce2f124a7]]
#### Observations
- [[occurrences/occ-74a0af71e03a7e1c.md|badscriptimport/index.html]]

### GET https://public-firing-range.appspot.com/clickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8ed05a727c56c159.md|Issue fin-8ed05a727c56c159]]
#### Observations
- [[occurrences/occ-71526eb562d59b5a.md|clickjacking]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_csp_no_frame_ancestors  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a946e93f203e4f91.md|Issue fin-a946e93f203e4f91]]
#### Observations
- [[occurrences/occ-bf032ef0ec138e2b.md|clickjacking_csp_no_frame_ancestors]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_xfo_allowall  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-70e9f5304ac14f9a.md|Issue fin-70e9f5304ac14f9a]]
#### Observations
- [[occurrences/occ-713c209e62eb735f.md|clickjacking_xfo_allowall]]

### GET https://public-firing-range.appspot.com/clickjacking/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b89fcb03a12238b.md|Issue fin-7b89fcb03a12238b]]
#### Observations
- [[occurrences/occ-6ad07ac27323e537.md|clickjacking/index.html]]

### GET https://public-firing-range.appspot.com/cors/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b9d8dd1f44c12cd.md|Issue fin-8b9d8dd1f44c12cd]]
#### Observations
- [[occurrences/occ-fb3107a3f579f6c7.md|cors]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowInsecureScheme  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2aa29c6a2ae346e6.md|Issue fin-2aa29c6a2ae346e6]]
#### Observations
- [[occurrences/occ-bc84c18417613b01.md|allowInsecureScheme]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-57b5eb653bc16a2a.md|Issue fin-57b5eb653bc16a2a]]
#### Observations
- [[occurrences/occ-4b0cafe3c09e1e77.md|allowNullOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3a025debc2b2b43b.md|Issue fin-3a025debc2b2b43b]]
#### Observations
- [[occurrences/occ-fce352883b68665f.md|allowNullOrigin]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c9daa17dbc8f3b9e.md|Issue fin-c9daa17dbc8f3b9e]]
#### Observations
- [[occurrences/occ-c33e589cd76885ea.md|allowOriginEndsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aef9c7a07a16ae8d.md|Issue fin-aef9c7a07a16ae8d]]
#### Observations
- [[occurrences/occ-c00da102139b3e61.md|allowOriginEndsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginProtocolDowngrade  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bdc0d32e15cdae23.md|Issue fin-bdc0d32e15cdae23]]
#### Observations
- [[occurrences/occ-92c9bbb22e494e8c.md|allowOriginProtocolDowngrade]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginRegexDot  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-538722c3dac8574f.md|Issue fin-538722c3dac8574f]]
#### Observations
- [[occurrences/occ-1c1da30a4f5524af.md|allowOriginRegexDot]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1a960a960552877e.md|Issue fin-1a960a960552877e]]
#### Observations
- [[occurrences/occ-be8cb8e97b544a96.md|allowOriginStartsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-82aa7a0ee352b1fb.md|Issue fin-82aa7a0ee352b1fb]]
#### Observations
- [[occurrences/occ-a9927b84b9467552.md|allowOriginStartsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1a7ad271c815b036.md|Issue fin-1a7ad271c815b036]]
#### Observations
- [[occurrences/occ-f54c0a4a21e07daa.md|dynamicAllowOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f3e7c24f0de9437e.md|Issue fin-f3e7c24f0de9437e]]
#### Observations
- [[occurrences/occ-650fbb132e74bf34.md|dynamicAllowOrigin]]

### GET https://public-firing-range.appspot.com/cors/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-210095085db66e7a.md|Issue fin-210095085db66e7a]]
#### Observations
- [[occurrences/occ-b19e0923fbcac5d2.md|cors/index.html]]

### GET https://public-firing-range.appspot.com/dom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3cac4302cdf86e6a.md|Issue fin-3cac4302cdf86e6a]]
#### Observations
- [[occurrences/occ-11b09fede9807374.md|dom]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3807515e7c3a6654.md|Issue fin-3807515e7c3a6654]]
#### Observations
- [[occurrences/occ-d6aba1b4f7c5c3b5.md|dompropagation]]

### GET https://public-firing-range.appspot.com/dom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5809f4c33903b47d.md|Issue fin-5809f4c33903b47d]]
#### Observations
- [[occurrences/occ-f9b68ccf87c969a2.md|dom/index.html]]

### GET https://public-firing-range.appspot.com/dom/javascripturi.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-deeb51213cbd9549.md|Issue fin-deeb51213cbd9549]]
#### Observations
- [[occurrences/occ-a9e047ca25379c57.md|javascripturi.html]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-991b792e547bb857.md|Issue fin-991b792e547bb857]]
#### Observations
- [[occurrences/occ-957551f6b311556b.md|complexMessageDocumentWriteEval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e8a885a486b1372e.md|Issue fin-e8a885a486b1372e]]
#### Observations
- [[occurrences/occ-b32df5f27dc84f94.md|documentWrite]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5fea521573a14e41.md|Issue fin-5fea521573a14e41]]
#### Observations
- [[occurrences/occ-e720772af2522e27.md|eval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bf673aded1a75dcb.md|Issue fin-bf673aded1a75dcb]]
#### Observations
- [[occurrences/occ-1a2c1d5e8d05b840.md|improperOriginValid…tialStringComparison]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-824ddf0adc776db4.md|Issue fin-824ddf0adc776db4]]
#### Observations
- [[occurrences/occ-c247d0f92a3bdc13.md|improperOriginValidationWithRegExp]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3a8cdf99759717d7.md|Issue fin-3a8cdf99759717d7]]
#### Observations
- [[occurrences/occ-6bfaeebeeeca0501.md|innerHtml]]

### GET https://public-firing-range.appspot.com/escape/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-df6515b39756c529.md|Issue fin-df6515b39756c529]]
#### Observations
- [[occurrences/occ-69d0783549d5ab32.md|escape]]

### GET https://public-firing-range.appspot.com/escape/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4e2e7898880048b4.md|Issue fin-4e2e7898880048b4]]
#### Observations
- [[occurrences/occ-8c647a682dd8b5a8.md|escape/index.html]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3d449e1ccc74944b.md|Issue fin-3d449e1ccc74944b]]
#### Observations
- [[occurrences/occ-c19f55b783d21574.md|encodeURIComponent]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f65b002aa4581fd0.md|Issue fin-f65b002aa4581fd0]]
#### Observations
- [[occurrences/occ-0041281ed47eefa1.md|escape]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7aa3227b7d686fe0.md|Issue fin-7aa3227b7d686fe0]]
#### Observations
- [[occurrences/occ-622e346e0e63cd4e.md|html_escape]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e0ad6873fe518eda.md|Issue fin-e0ad6873fe518eda]]
#### Observations
- [[occurrences/occ-7413645199676dd0.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d5cefc6bc9c6ca5a.md|Issue fin-d5cefc6bc9c6ca5a]]
#### Observations
- [[occurrences/occ-37b182f793605147.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2bf8616d5def3fe9.md|Issue fin-2bf8616d5def3fe9]]
#### Observations
- [[occurrences/occ-50055dcf786b3c41.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b3df2f17d62a9932.md|Issue fin-b3df2f17d62a9932]]
#### Observations
- [[occurrences/occ-a971eb7146c7697a.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-28ed676e41581bf4.md|Issue fin-28ed676e41581bf4]]
#### Observations
- [[occurrences/occ-5fd93d9237dd6b80.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-792ad1ba1bb9b9ed.md|Issue fin-792ad1ba1bb9b9ed]]
#### Observations
- [[occurrences/occ-c51d5cbe837d6522.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2497d4a4a2301a2a.md|Issue fin-2497d4a4a2301a2a]]
#### Observations
- [[occurrences/occ-f24fa7c7b4ca4775.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dd7612cc170423b4.md|Issue fin-dd7612cc170423b4]]
#### Observations
- [[occurrences/occ-cfe4dc541cde7ce2.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8ba7741f76c660b1.md|Issue fin-8ba7741f76c660b1]]
#### Observations
- [[occurrences/occ-8cc8f86fa9244a16.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3943fdfe54b03dc9.md|Issue fin-3943fdfe54b03dc9]]
#### Observations
- [[occurrences/occ-085c07ce8fb447e0.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fd50dc90d0d23fa0.md|Issue fin-fd50dc90d0d23fa0]]
#### Observations
- [[occurrences/occ-c86f34f2785565e9.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2b563099aed63e94.md|Issue fin-2b563099aed63e94]]
#### Observations
- [[occurrences/occ-da823abfbbc16ed6.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f7a58e84fe11d0e7.md|Issue fin-f7a58e84fe11d0e7]]
#### Observations
- [[occurrences/occ-4dd26577a08a1988.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-908c99947d6d8ce6.md|Issue fin-908c99947d6d8ce6]]
#### Observations
- [[occurrences/occ-735df02bd608249e.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-32be14ce25af33c0.md|Issue fin-32be14ce25af33c0]]
#### Observations
- [[occurrences/occ-17a74eb974518d08.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-960e58754930a634.md|Issue fin-960e58754930a634]]
#### Observations
- [[occurrences/occ-36e62f342bc9bf3b.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6f3f7bdde5abd753.md|Issue fin-6f3f7bdde5abd753]]
#### Observations
- [[occurrences/occ-f790a9a951c1e579.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4cd65b7636725b13.md|Issue fin-4cd65b7636725b13]]
#### Observations
- [[occurrences/occ-f13b0dc170ad8f41.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-52f61bf6ff31a350.md|Issue fin-52f61bf6ff31a350]]
#### Observations
- [[occurrences/occ-6202c40d05a808f3.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-89b86e805fbc6a8f.md|Issue fin-89b86e805fbc6a8f]]
#### Observations
- [[occurrences/occ-9b2d4044b5de8a6a.md|textarea]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bd57c451400f4c1e.md|Issue fin-bd57c451400f4c1e]]
#### Observations
- [[occurrences/occ-64fe30d0c7a20438.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4202956aee29a827.md|Issue fin-4202956aee29a827]]
#### Observations
- [[occurrences/occ-40e081ba5b7c5f8e.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c46e06680ecc4631.md|Issue fin-c46e06680ecc4631]]
#### Observations
- [[occurrences/occ-5b235d2910e214ee.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-79b5dabefce43dbc.md|Issue fin-79b5dabefce43dbc]]
#### Observations
- [[occurrences/occ-bd77f4a83c9be6d1.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9ba78cd0938c0ece.md|Issue fin-9ba78cd0938c0ece]]
#### Observations
- [[occurrences/occ-5a3331292df569c4.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-878a79a721e975c9.md|Issue fin-878a79a721e975c9]]
#### Observations
- [[occurrences/occ-86076b086dca234f.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0d5ee191122b57f5.md|Issue fin-0d5ee191122b57f5]]
#### Observations
- [[occurrences/occ-384e7202468d95ab.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5b78a520c25537fe.md|Issue fin-5b78a520c25537fe]]
#### Observations
- [[occurrences/occ-a1899e622099c89f.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a3ce32b7528bd141.md|Issue fin-a3ce32b7528bd141]]
#### Observations
- [[occurrences/occ-dc759ee38eb8a6fe.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-391ef49540289187.md|Issue fin-391ef49540289187]]
#### Observations
- [[occurrences/occ-5ab20b4fbd53744c.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_value?q=a&escape=HTML_ESCAPE  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce1105180a0094bb.md|Issue fin-ce1105180a0094bb]]
#### Observations
- [[occurrences/occ-b595a109273dfcd5.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e928f1988ae123c4.md|Issue fin-e928f1988ae123c4]]
#### Observations
- [[occurrences/occ-028fe0eeaaca2c56.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-45b0d033fc932b43.md|Issue fin-45b0d033fc932b43]]
#### Observations
- [[occurrences/occ-2dedaac2f1014a15.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-90b16ec373c494e6.md|Issue fin-90b16ec373c494e6]]
#### Observations
- [[occurrences/occ-b0152e78745b0644.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-93ecbf13a2e19d5c.md|Issue fin-93ecbf13a2e19d5c]]
#### Observations
- [[occurrences/occ-85c22473b31fbfa4.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f073b378b8439871.md|Issue fin-f073b378b8439871]]
#### Observations
- [[occurrences/occ-37614217068380f5.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b9fc8defd7607573.md|Issue fin-b9fc8defd7607573]]
#### Observations
- [[occurrences/occ-5a3be2776c29d7e3.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8e4e4f05c3dfbd33.md|Issue fin-8e4e4f05c3dfbd33]]
#### Observations
- [[occurrences/occ-1ca0f6a421257dfe.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2e1636cad7132b5f.md|Issue fin-2e1636cad7132b5f]]
#### Observations
- [[occurrences/occ-9df3b8409f16f03c.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de83adda1dc26f98.md|Issue fin-de83adda1dc26f98]]
#### Observations
- [[occurrences/occ-52dd60f58f806396.md|textarea]]

### GET https://public-firing-range.appspot.com/favicon.ico  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-32d40f7aeabf2d49.md|Issue fin-32d40f7aeabf2d49]]
#### Observations
- [[occurrences/occ-a1834a34625f6670.md|favicon.ico]]

### GET https://public-firing-range.appspot.com/flashinjection/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f1695d346ed00759.md|Issue fin-f1695d346ed00759]]
#### Observations
- [[occurrences/occ-4dc6076d1c31e33c.md|flashinjection]]

### GET https://public-firing-range.appspot.com/flashinjection/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de30c10f68a579a5.md|Issue fin-de30c10f68a579a5]]
#### Observations
- [[occurrences/occ-412c283250b39841.md|flashinjection/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-84c9a7043feebd24.md|Issue fin-84c9a7043feebd24]]
#### Observations
- [[occurrences/occ-c20d1905bc6b9e64.md|insecurethirdpartyscripts]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9b82bb7c1407df89.md|Issue fin-9b82bb7c1407df89]]
#### Observations
- [[occurrences/occ-693fefa2727bdbac.md|insecurethirdpartyscripts/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-535e903ebe156586.md|Issue fin-535e903ebe156586]]
#### Observations
- [[occurrences/occ-4effb63cc7bc5c37.md|third_party_scripts…ource_integrity.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f8c676e64406e82a.md|Issue fin-f8c676e64406e82a]]
#### Observations
- [[occurrences/occ-473d72e3e98f4915.md|third_party_scripts…namically_added.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2e3436c39e566640.md|Issue fin-2e3436c39e566640]]
#### Observations
- [[occurrences/occ-ead76b7a0650714f.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d79a52339630153e.md|Issue fin-d79a52339630153e]]
#### Observations
- [[occurrences/occ-638a669ead970967.md|leakedcookie/index.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c01a259a7f1c74e4.md|Issue fin-c01a259a7f1c74e4]]
#### Observations
- [[occurrences/occ-96eb80d9faa0c59c.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b084ffdf99431f87.md|Issue fin-b084ffdf99431f87]]
#### Observations
- [[occurrences/occ-2dd65a649ff18315.md|leakedinresource]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ffcc9273457c0fa.md|Issue fin-0ffcc9273457c0fa]]
#### Observations
- [[occurrences/occ-c690617e030f05f6.md|mixedcontent]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-35b58aabb17b4a36.md|Issue fin-35b58aabb17b4a36]]
#### Observations
- [[occurrences/occ-5ca241361807f3ba.md|mixedcontent/index.html]]

### GET https://public-firing-range.appspot.com/redirect/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-699015b89be0293d.md|Issue fin-699015b89be0293d]]
#### Observations
- [[occurrences/occ-c86f712c0d2b4be6.md|redirect]]

### GET https://public-firing-range.appspot.com/redirect/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-96296f82d6986d6b.md|Issue fin-96296f82d6986d6b]]
#### Observations
- [[occurrences/occ-b332eb8e8d626b18.md|redirect/index.html]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-558f2606c87aa68d.md|Issue fin-558f2606c87aa68d]]
#### Observations
- [[occurrences/occ-79e65a7df2390a39.md|meta]]

### GET https://public-firing-range.appspot.com/reflected/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-337aa483be18f48d.md|Issue fin-337aa483be18f48d]]
#### Observations
- [[occurrences/occ-4cebc51261b58877.md|reflected]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b6bc50b6fe6e6f7d.md|Issue fin-b6bc50b6fe6e6f7d]]
#### Observations
- [[occurrences/occ-557969126d43079c.md|DOUBLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-150415290068c45b.md|Issue fin-150415290068c45b]]
#### Observations
- [[occurrences/occ-afa512016b9b7b88.md|SINGLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-50f0ff4436055972.md|Issue fin-50f0ff4436055972]]
#### Observations
- [[occurrences/occ-b13e7f345c630277.md|UNQUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0f5a7a19f15ac33e.md|Issue fin-0f5a7a19f15ac33e]]
#### Observations
- [[occurrences/occ-3c6780a157d4493f.md|DoubleQuoteSinglequote]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-60e15454d12e0433.md|Issue fin-60e15454d12e0433]]
#### Observations
- [[occurrences/occ-1cced461ef486730.md|SpaceDoubleQuoteSlashEquals]]

### GET https://public-firing-range.appspot.com/reflected/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eeb0664a063c9654.md|Issue fin-eeb0664a063c9654]]
#### Observations
- [[occurrences/occ-93823c388c49c220.md|reflected/index.html]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-491b2efcf4b32e83.md|Issue fin-491b2efcf4b32e83]]
#### Observations
- [[occurrences/occ-767850fe624cd852.md|attribute_name]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-137410eec6b2f17c.md|Issue fin-137410eec6b2f17c]]
#### Observations
- [[occurrences/occ-9678490132746ff4.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-276e265d93a6ed15.md|Issue fin-276e265d93a6ed15]]
#### Observations
- [[occurrences/occ-086867970b09c9cc.md|attribute_script]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b4c085110578a84.md|Issue fin-8b4c085110578a84]]
#### Observations
- [[occurrences/occ-96380157af912613.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bfe54d26a6f88a30.md|Issue fin-bfe54d26a6f88a30]]
#### Observations
- [[occurrences/occ-fa217ca5712b66d1.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/400?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e34e249538e85acd.md|Issue fin-e34e249538e85acd]]
#### Observations
- [[occurrences/occ-61da3e6c1ebfec24.md|400]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/401?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7c44a90ccdf8be25.md|Issue fin-7c44a90ccdf8be25]]
#### Observations
- [[occurrences/occ-18dfc9f9ac2d2f95.md|401]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/403?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-30614805c2abf8e6.md|Issue fin-30614805c2abf8e6]]
#### Observations
- [[occurrences/occ-88aa9047a852142a.md|403]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/404?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3d3e087b30f9c41a.md|Issue fin-3d3e087b30f9c41a]]
#### Observations
- [[occurrences/occ-3a30009c2f74a3c9.md|404]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/500?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f90578745a64c32f.md|Issue fin-f90578745a64c32f]]
#### Observations
- [[occurrences/occ-9a33ec5986c3dc2c.md|500]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-26bb6d53143c2362.md|Issue fin-26bb6d53143c2362]]
#### Observations
- [[occurrences/occ-7e26b6c63b742ca5.md|body]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eca950099cf7d945.md|Issue fin-eca950099cf7d945]]
#### Observations
- [[occurrences/occ-7273819f8e0a93b7.md|body_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f59bd948715b7001.md|Issue fin-f59bd948715b7001]]
#### Observations
- [[occurrences/occ-9229b5a765ee3547.md|css_style]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f914b72456904796.md|Issue fin-f914b72456904796]]
#### Observations
- [[occurrences/occ-7aacb0fd132ec087.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2be248e81530ce74.md|Issue fin-2be248e81530ce74]]
#### Observations
- [[occurrences/occ-0a4721c1c80d0f43.md|css_style_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/form  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1631b648caea2338.md|Issue fin-1631b648caea2338]]
#### Observations
- [[occurrences/occ-e581168280ae736a.md|form]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5700c0850cf6c5d8.md|Issue fin-5700c0850cf6c5d8]]
#### Observations
- [[occurrences/occ-1a13208146162b2d.md|head]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-61c43b9c1115114c.md|Issue fin-61c43b9c1115114c]]
#### Observations
- [[occurrences/occ-9aad5b2dee44e218.md|iframe_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b42b394627522012.md|Issue fin-b42b394627522012]]
#### Observations
- [[occurrences/occ-f962029691fa5d8c.md|iframe_srcdoc]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8aa044ded9da4efd.md|Issue fin-8aa044ded9da4efd]]
#### Observations
- [[occurrences/occ-8cf9c6b0628d3e60.md|js_assignment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e0424fe32099a73e.md|Issue fin-e0424fe32099a73e]]
#### Observations
- [[occurrences/occ-85f5541ed99d892b.md|js_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7ee39c53dbab930f.md|Issue fin-7ee39c53dbab930f]]
#### Observations
- [[occurrences/occ-ee76181d7b3ac0ea.md|js_eval]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3210eb7138e08659.md|Issue fin-3210eb7138e08659]]
#### Observations
- [[occurrences/occ-0f117dcc0defbc37.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-06b56063321552ec.md|Issue fin-06b56063321552ec]]
#### Observations
- [[occurrences/occ-6bc8071e17f88128.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e42ee4013649a210.md|Issue fin-e42ee4013649a210]]
#### Observations
- [[occurrences/occ-7e8517d63c0aa009.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6755d2457b31907d.md|Issue fin-6755d2457b31907d]]
#### Observations
- [[occurrences/occ-3917ccab4b21fc5c.md|json]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a1a8a99210b82569.md|Issue fin-a1a8a99210b82569]]
#### Observations
- [[occurrences/occ-bd002bc2de0029f3.md|noscript]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a9899c0163edf060.md|Issue fin-a9899c0163edf060]]
#### Observations
- [[occurrences/occ-d5385cba49550034.md|style_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ccf8337f6381d224.md|Issue fin-ccf8337f6381d224]]
#### Observations
- [[occurrences/occ-70146bf25e51ee03.md|tagname]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-391e11fc9ecb2c97.md|Issue fin-391e11fc9ecb2c97]]
#### Observations
- [[occurrences/occ-47844b4daeea794b.md|textarea]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec9721f14741c2ec.md|Issue fin-ec9721f14741c2ec]]
#### Observations
- [[occurrences/occ-65afa2fce161e8f0.md|textarea_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d5fb28020c44f9b6.md|Issue fin-d5fb28020c44f9b6]]
#### Observations
- [[occurrences/occ-d6206623c475ad94.md|title]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3d767ab76e7e2d94.md|Issue fin-3d767ab76e7e2d94]]
#### Observations
- [[occurrences/occ-35ede90275cc0311.md|css_import]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-99b1e520a56db780.md|Issue fin-99b1e520a56db780]]
#### Observations
- [[occurrences/occ-4c69d5037bd382ff.md|href]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e1c720cd2b86ea28.md|Issue fin-e1c720cd2b86ea28]]
#### Observations
- [[occurrences/occ-8c42552448c1890c.md|object_data]]

### GET https://public-firing-range.appspot.com/reflected/url/object_param?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7017d48d301fb52f.md|Issue fin-7017d48d301fb52f]]
#### Observations
- [[occurrences/occ-d0ea562c7f3d0379.md|object_param]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dfcea08303df6853.md|Issue fin-dfcea08303df6853]]
#### Observations
- [[occurrences/occ-59dc54f081025f72.md|script_src]]

### GET https://public-firing-range.appspot.com/remoteinclude/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c43ff8d5c0cb282c.md|Issue fin-c43ff8d5c0cb282c]]
#### Observations
- [[occurrences/occ-38fa13a151678894.md|remoteinclude]]

### GET https://public-firing-range.appspot.com/remoteinclude/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a37c6f0148a8f3c4.md|Issue fin-a37c6f0148a8f3c4]]
#### Observations
- [[occurrences/occ-db7f40bdb63cd5e8.md|remoteinclude/index.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-49bb3fe18f91971e.md|Issue fin-49bb3fe18f91971e]]
#### Observations
- [[occurrences/occ-581fd35ff4c5b123.md|object_hash.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c810debd9390e2e.md|Issue fin-0c810debd9390e2e]]
#### Observations
- [[occurrences/occ-4fd588bb369435c7.md|application_x-shockwave-flash]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fa113a5f454a4a08.md|Issue fin-fa113a5f454a4a08]]
#### Observations
- [[occurrences/occ-a243dd3f0042690d.md|object_raw]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-079a4116d1caf47d.md|Issue fin-079a4116d1caf47d]]
#### Observations
- [[occurrences/occ-6f3c46ccbbd423c4.md|script]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-86a79b80cb9ffa0d.md|Issue fin-86a79b80cb9ffa0d]]
#### Observations
- [[occurrences/occ-964e46534d178630.md|script_hash.html]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8c17ba32764e0a93.md|Issue fin-8c17ba32764e0a93]]
#### Observations
- [[occurrences/occ-e7126db5632d3b4d.md|reverseclickjacking]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b78cf426e73099d9.md|Issue fin-b78cf426e73099d9]]
#### Observations
- [[occurrences/occ-8d9afa9d5f2dbe63.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3b83aeedb36f9a37.md|Issue fin-3b83aeedb36f9a37]]
#### Observations
- [[occurrences/occ-a03e4b209e421ef6.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-53989fce41f55fcc.md|Issue fin-53989fce41f55fcc]]
#### Observations
- [[occurrences/occ-e2383c3c417657cf.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a13f51fd21bc31c5.md|Issue fin-a13f51fd21bc31c5]]
#### Observations
- [[occurrences/occ-1335ee90f93e39cd.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-55e1c2904faa273b.md|Issue fin-55e1c2904faa273b]]
#### Observations
- [[occurrences/occ-110d88055cd08b56.md|stricttransportsecurity]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_includesubdomains_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e9aed1ac6809fb4f.md|Issue fin-e9aed1ac6809fb4f]]
#### Observations
- [[occurrences/occ-d520d1eb1cce756e.md|hsts_includesubdomains_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-83056170cd55e24d.md|Issue fin-83056170cd55e24d]]
#### Observations
- [[occurrences/occ-f54025330bf08e48.md|hsts_max_age_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_too_low  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bbbfb36e7256b3ec.md|Issue fin-bbbfb36e7256b3ec]]
#### Observations
- [[occurrences/occ-00fe54e31745eecb.md|hsts_max_age_too_low]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2d8ce9ba5abd1d3c.md|Issue fin-2d8ce9ba5abd1d3c]]
#### Observations
- [[occurrences/occ-b644e471d66747f3.md|hsts_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_preload_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2c52dbaadca9a039.md|Issue fin-2c52dbaadca9a039]]
#### Observations
- [[occurrences/occ-e3d6206da7861bd2.md|hsts_preload_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9d9ebe5c6edeb5cf.md|Issue fin-9d9ebe5c6edeb5cf]]
#### Observations
- [[occurrences/occ-774f48bbd425f56e.md|stricttransportsecurity/index.html]]

### GET https://public-firing-range.appspot.com/tags/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-711632b4f04341c2.md|Issue fin-711632b4f04341c2]]
#### Observations
- [[occurrences/occ-5b2de4b32dc9295c.md|tags]]

### GET https://public-firing-range.appspot.com/tags/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d6f81e7aa0b4427f.md|Issue fin-d6f81e7aa0b4427f]]
#### Observations
- [[occurrences/occ-dbf913ba2c0eb1b1.md|tags/index.html]]

### GET https://public-firing-range.appspot.com/tags/multiline?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-16367b8eb26bdac8.md|Issue fin-16367b8eb26bdac8]]
#### Observations
- [[occurrences/occ-5375782e79ddc8a5.md|multiline]]

### GET https://public-firing-range.appspot.com/urldom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b5fefdde83fbd1a5.md|Issue fin-b5fefdde83fbd1a5]]
#### Observations
- [[occurrences/occ-e5dfc23965bf9cf9.md|urldom]]

### GET https://public-firing-range.appspot.com/urldom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eed361147306da26.md|Issue fin-eed361147306da26]]
#### Observations
- [[occurrences/occ-2a07d5bc560653f0.md|urldom/index.html]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_domain  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-79d147e111342825.md|Issue fin-79d147e111342825]]
#### Observations
- [[occurrences/occ-1d6c232581e89456.md|script.src.partial_domain]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_query  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e72e39b59a46c70a.md|Issue fin-e72e39b59a46c70a]]
#### Observations
- [[occurrences/occ-e9e415cb0e5333cd.md|script.src.partial_query]]

### GET https://public-firing-range.appspot.com/urldom/location/search/area.href?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7df0d71b03d2c932.md|Issue fin-7df0d71b03d2c932]]
#### Observations
- [[occurrences/occ-a5d69dd778aec8c1.md|area.href]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b4c7a8bb8a6f9a1b.md|Issue fin-b4c7a8bb8a6f9a1b]]
#### Observations
- [[occurrences/occ-8cae34b7d6b8632f.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-26dd29e9041e8e6f.md|Issue fin-26dd29e9041e8e6f]]
#### Observations
- [[occurrences/occ-55ad6c49fdb18b78.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/frame.src?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-86716b7924f63bf6.md|Issue fin-86716b7924f63bf6]]
#### Observations
- [[occurrences/occ-1462d404b00b9476.md|frame.src]]

### GET https://public-firing-range.appspot.com/urldom/location/search/location.assign?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-43cf9a7306fe1eda.md|Issue fin-43cf9a7306fe1eda]]
#### Observations
- [[occurrences/occ-fd00c0cc4313f915.md|location.assign]]

### GET https://public-firing-range.appspot.com/urldom/location/search/svg.a?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f71e03159aaeb98a.md|Issue fin-f71e03159aaeb98a]]
#### Observations
- [[occurrences/occ-f242a75ea58119c9.md|svg.a]]

### GET https://public-firing-range.appspot.com/urldom/script.js  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c05c4cc6eeb5ab87.md|Issue fin-c05c4cc6eeb5ab87]]
#### Observations
- [[occurrences/occ-ada7f9c7f77c58b4.md|script.js]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a48cc64ab0b62bf3.md|Issue fin-a48cc64ab0b62bf3]]
#### Observations
- [[occurrences/occ-556c824268e1891d.md|vulnerablelibraries]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8d1bc813e12baebb.md|Issue fin-8d1bc813e12baebb]]
#### Observations
- [[occurrences/occ-9a40c1f20ca1cd49.md|vulnerablelibraries/index.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2fd10e002e539e5a.md|Issue fin-2fd10e002e539e5a]]
#### Observations
- [[occurrences/occ-1475beec4d91fb9a.md|jquery.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/x  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5b2f683927b58a15.md|Issue fin-5b2f683927b58a15]]
#### Observations
- [[occurrences/occ-d478cb3af0bbc63d.md|x]]

