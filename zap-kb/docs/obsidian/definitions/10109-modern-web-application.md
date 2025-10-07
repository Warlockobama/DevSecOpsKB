---
aliases:
  - "MWA-0109"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10109"
name: "Modern Web Application"
occurrenceCount: "113"
pluginId: "10109"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "113"
---

# Modern Web Application (Plugin 10109)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ModernAppDetectionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ModernAppDetectionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10109/

### How it detects

Passive; sets evidence

## Remediation

This is an informational alert and so no changes are required.

## Issues

### GET https://public-firing-range.appspot.com/address/URL/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2fc6c258097cab67.md|Issue fin-2fc6c258097cab67]]
#### Observations
- [[occurrences/occ-b7c0391ee17c7da9.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/URLUnencoded/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1a3bacc0b4d18182.md|Issue fin-1a3bacc0b4d18182]]
#### Observations
- [[occurrences/occ-b97405bfeece4826.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/baseURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-137021689c742e7c.md|Issue fin-137021689c742e7c]]
#### Observations
- [[occurrences/occ-b59feda0211faf7e.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/documentURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6720eef734746f6e.md|Issue fin-6720eef734746f6e]]
#### Observations
- [[occurrences/occ-d282d408e5a9e084.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location.hash/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ae9d4da2da1e90c5.md|Issue fin-ae9d4da2da1e90c5]]
#### Observations
- [[occurrences/occ-fa2ca66c74a031ff.md|assign]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-38fa29e417d96413.md|Issue fin-38fa29e417d96413]]
#### Observations
- [[occurrences/occ-0b5008e4b8f31ed4.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ac068d8191a9dd4.md|Issue fin-0ac068d8191a9dd4]]
#### Observations
- [[occurrences/occ-d5f5af3655502fed.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-af72c14291fe3962.md|Issue fin-af72c14291fe3962]]
#### Observations
- [[occurrences/occ-b9366b8de8f90e23.md|eval]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-72575e5259e19129.md|Issue fin-72575e5259e19129]]
#### Observations
- [[occurrences/occ-5536d3060c5118c5.md|formaction]]

### GET https://public-firing-range.appspot.com/address/location.hash/function  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4dd3ef2848659545.md|Issue fin-4dd3ef2848659545]]
#### Observations
- [[occurrences/occ-06f6fee4b225b1a4.md|function]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a2c853ee7954751d.md|Issue fin-a2c853ee7954751d]]
#### Observations
- [[occurrences/occ-230b1e3093d98652.md|inlineevent]]

### GET https://public-firing-range.appspot.com/address/location.hash/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1bfa43e3127d4271.md|Issue fin-1bfa43e3127d4271]]
#### Observations
- [[occurrences/occ-ab4ead9fdca2b338.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location.hash/jshref  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-46d0ab9415d7962a.md|Issue fin-46d0ab9415d7962a]]
#### Observations
- [[occurrences/occ-03c867cf745c7ba8.md|jshref]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickAddEventListener  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e64b633e0085f7ab.md|Issue fin-e64b633e0085f7ab]]
#### Observations
- [[occurrences/occ-da98299e999b92fd.md|onclickAddEventListener]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickSetAttribute  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-360ee52be5748d71.md|Issue fin-360ee52be5748d71]]
#### Observations
- [[occurrences/occ-398ae987df81d6de.md|onclickSetAttribute]]

### GET https://public-firing-range.appspot.com/address/location.hash/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4ef06ba2733c6255.md|Issue fin-4ef06ba2733c6255]]
#### Observations
- [[occurrences/occ-20fd8de52d3b2797.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c530789bd55f4aba.md|Issue fin-c530789bd55f4aba]]
#### Observations
- [[occurrences/occ-89cc12b025efb5e1.md|replace]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-859bcea6bbda96b5.md|Issue fin-859bcea6bbda96b5]]
#### Observations
- [[occurrences/occ-12c2a5c8072872c9.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/location/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db796f39925899de.md|Issue fin-db796f39925899de]]
#### Observations
- [[occurrences/occ-7c4cf2f5ac099359.md|assign]]

### GET https://public-firing-range.appspot.com/address/location/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-53ff48e15579a758.md|Issue fin-53ff48e15579a758]]
#### Observations
- [[occurrences/occ-44ee386d217e7da7.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5303d76ea7449349.md|Issue fin-5303d76ea7449349]]
#### Observations
- [[occurrences/occ-0987c2bfbe40d5e8.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-52908931f67e5f2c.md|Issue fin-52908931f67e5f2c]]
#### Observations
- [[occurrences/occ-7067967ead6f3e36.md|eval]]

### GET https://public-firing-range.appspot.com/address/location/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-619e553b9be020ca.md|Issue fin-619e553b9be020ca]]
#### Observations
- [[occurrences/occ-34954a1f25a645c1.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b976f02bc619a17f.md|Issue fin-b976f02bc619a17f]]
#### Observations
- [[occurrences/occ-cbe9696727583d98.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dea12c61a6bb214e.md|Issue fin-dea12c61a6bb214e]]
#### Observations
- [[occurrences/occ-752b042fd6cc38d3.md|replace]]

### GET https://public-firing-range.appspot.com/address/location/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f801667d22ac6ec6.md|Issue fin-f801667d22ac6ec6]]
#### Observations
- [[occurrences/occ-369337cbaebe30a4.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/locationhref/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce2c0748ce7cb7fa.md|Issue fin-ce2c0748ce7cb7fa]]
#### Observations
- [[occurrences/occ-1eddaa9e05466b6b.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationpathname/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-80d43fc837de586d.md|Issue fin-80d43fc837de586d]]
#### Observations
- [[occurrences/occ-a2639d0d7ca3ab5a.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationsearch/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c13222736e879681.md|Issue fin-c13222736e879681]]
#### Observations
- [[occurrences/occ-5a3aa187c4e1f57b.md|documentwrite]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-018b126d00f54845.md|Issue fin-018b126d00f54845]]
#### Observations
- [[occurrences/occ-edd55d3a376effe1.md|1.1.5]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-36d27e4124c946a0.md|Issue fin-36d27e4124c946a0]]
#### Observations
- [[occurrences/occ-c5c0340198489f6e.md|1.2.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-39be97d8cdda5dee.md|Issue fin-39be97d8cdda5dee]]
#### Observations
- [[occurrences/occ-f006d01b2b40a8c2.md|1.2.18]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c3832acead762c1b.md|Issue fin-c3832acead762c1b]]
#### Observations
- [[occurrences/occ-9c8f84819525ea80.md|1.2.19]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b32c9e5f58e4e811.md|Issue fin-b32c9e5f58e4e811]]
#### Observations
- [[occurrences/occ-18329e65528ecafb.md|1.2.24]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6b6985fb3b0395e4.md|Issue fin-6b6985fb3b0395e4]]
#### Observations
- [[occurrences/occ-b1ab3d7037dc1620.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-547c3d486ad63149.md|Issue fin-547c3d486ad63149]]
#### Observations
- [[occurrences/occ-a3e01c412fcde699.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-edeb1e75ba5bd5aa.md|Issue fin-edeb1e75ba5bd5aa]]
#### Observations
- [[occurrences/occ-aa1b6758f8ab5a0a.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0b7149300f890cf4.md|Issue fin-0b7149300f890cf4]]
#### Observations
- [[occurrences/occ-64ae07471cfca210.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-11a6b33e3841ca52.md|Issue fin-11a6b33e3841ca52]]
#### Observations
- [[occurrences/occ-c6fece64de5b2b38.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d170931f76b8e826.md|Issue fin-d170931f76b8e826]]
#### Observations
- [[occurrences/occ-57c0d3acf60f8fb8.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9ea2bb8b8cc146b2.md|Issue fin-9ea2bb8b8cc146b2]]
#### Observations
- [[occurrences/occ-045c46803d307321.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1eeadd4a668064f9.md|Issue fin-1eeadd4a668064f9]]
#### Observations
- [[occurrences/occ-3c8ed3a97507e6a0.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b536f13de05359ea.md|Issue fin-b536f13de05359ea]]
#### Observations
- [[occurrences/occ-9cd03163b0b15b72.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a18fba42006f3b34.md|Issue fin-a18fba42006f3b34]]
#### Observations
- [[occurrences/occ-e46024277bb322c0.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b84f7ad716a55fb.md|Issue fin-8b84f7ad716a55fb]]
#### Observations
- [[occurrences/occ-ef0b22cb70c5c6ff.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9089c058adce2724.md|Issue fin-9089c058adce2724]]
#### Observations
- [[occurrences/occ-89fcbd50ac65ffd1.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-216c48fb06928a71.md|Issue fin-216c48fb06928a71]]
#### Observations
- [[occurrences/occ-a13a5ea8e50100f1.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8ce85c096e6a7e88.md|Issue fin-8ce85c096e6a7e88]]
#### Observations
- [[occurrences/occ-bff7995a73f35d3b.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5bb014f8e878b50e.md|Issue fin-5bb014f8e878b50e]]
#### Observations
- [[occurrences/occ-0dbbb7f4b0e63e06.md|1.6.0]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowInsecureScheme  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d77501b032aa95d4.md|Issue fin-d77501b032aa95d4]]
#### Observations
- [[occurrences/occ-d9cf42d2f00967b3.md|allowInsecureScheme]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2cadbe55a2a3ff5a.md|Issue fin-2cadbe55a2a3ff5a]]
#### Observations
- [[occurrences/occ-a17de8c80af6fbb6.md|allowNullOrigin]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6078b677e8c627ad.md|Issue fin-6078b677e8c627ad]]
#### Observations
- [[occurrences/occ-4e4916f34f1bda22.md|allowOriginEndsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginProtocolDowngrade  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-89ff5a8b7d13054f.md|Issue fin-89ff5a8b7d13054f]]
#### Observations
- [[occurrences/occ-c28f1f75964024d0.md|allowOriginProtocolDowngrade]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginRegexDot  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4e58f6ded379ab62.md|Issue fin-4e58f6ded379ab62]]
#### Observations
- [[occurrences/occ-5edc9d89857ae765.md|allowOriginRegexDot]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c9ec484d14fcb1d7.md|Issue fin-c9ec484d14fcb1d7]]
#### Observations
- [[occurrences/occ-03b41cb8724d8002.md|allowOriginStartsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b1ddacb4a31c6875.md|Issue fin-b1ddacb4a31c6875]]
#### Observations
- [[occurrences/occ-b05cb482db247c2f.md|dynamicAllowOrigin]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b1397e1ad876cdb.md|Issue fin-7b1397e1ad876cdb]]
#### Observations
- [[occurrences/occ-9e112639939b8e37.md|dompropagation]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a1c23554011500f8.md|Issue fin-a1c23554011500f8]]
#### Observations
- [[occurrences/occ-30fe7832ece57466.md|complexMessageDocumentWriteEval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8f24797ea1721641.md|Issue fin-8f24797ea1721641]]
#### Observations
- [[occurrences/occ-8e51c174dae6ffe5.md|documentWrite]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-962bcb5413cbf4c6.md|Issue fin-962bcb5413cbf4c6]]
#### Observations
- [[occurrences/occ-a2a22da7de81f334.md|eval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1ec68e1b101da9d0.md|Issue fin-1ec68e1b101da9d0]]
#### Observations
- [[occurrences/occ-52a3c10b75a3b48d.md|improperOriginValid…tialStringComparison]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-71f28a8830a88d44.md|Issue fin-71f28a8830a88d44]]
#### Observations
- [[occurrences/occ-35e5f888e8a96ac4.md|improperOriginValidationWithRegExp]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c7f6cea35cc36e69.md|Issue fin-c7f6cea35cc36e69]]
#### Observations
- [[occurrences/occ-6e14dcec0a30300c.md|innerHtml]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3e8d4d4260cfae69.md|Issue fin-3e8d4d4260cfae69]]
#### Observations
- [[occurrences/occ-0704626d660b6b7f.md|encodeURIComponent]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-46d74c78940bbf4a.md|Issue fin-46d74c78940bbf4a]]
#### Observations
- [[occurrences/occ-f02450028da1be57.md|escape]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5325bc65899f836e.md|Issue fin-5325bc65899f836e]]
#### Observations
- [[occurrences/occ-11abfc59cea24e13.md|html_escape]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f964994bb48abe1c.md|Issue fin-f964994bb48abe1c]]
#### Observations
- [[occurrences/occ-322648a7e690540b.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d0fe1c02a278961b.md|Issue fin-d0fe1c02a278961b]]
#### Observations
- [[occurrences/occ-fb07406aa8bf11f2.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c68b5e0ce45e03b6.md|Issue fin-c68b5e0ce45e03b6]]
#### Observations
- [[occurrences/occ-045e4205207cdcfc.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9b4e33c7a8e10367.md|Issue fin-9b4e33c7a8e10367]]
#### Observations
- [[occurrences/occ-5be942e8d77a9a10.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-24882b01a652603c.md|Issue fin-24882b01a652603c]]
#### Observations
- [[occurrences/occ-280941b474e71935.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3179e0d7177adbbf.md|Issue fin-3179e0d7177adbbf]]
#### Observations
- [[occurrences/occ-32bb5c8433c6b7a8.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b3d264644c5e9343.md|Issue fin-b3d264644c5e9343]]
#### Observations
- [[occurrences/occ-f0bbe056de8ac5c2.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec208a0ac38203b7.md|Issue fin-ec208a0ac38203b7]]
#### Observations
- [[occurrences/occ-ae5aa0a3c7c91c4d.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3c8ee5de5f09f4d4.md|Issue fin-3c8ee5de5f09f4d4]]
#### Observations
- [[occurrences/occ-ed6c43fd84a4d775.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-972d4f1943ae36a8.md|Issue fin-972d4f1943ae36a8]]
#### Observations
- [[occurrences/occ-0f63bfae6c7ccee6.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-72bb1059d43cf2fa.md|Issue fin-72bb1059d43cf2fa]]
#### Observations
- [[occurrences/occ-4e3c703da15af897.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3083b49da48ab95e.md|Issue fin-3083b49da48ab95e]]
#### Observations
- [[occurrences/occ-03847ca56eac0619.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-27657ddc835e6655.md|Issue fin-27657ddc835e6655]]
#### Observations
- [[occurrences/occ-baf6334bf1462dcd.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ab3bc3ca2bf3d644.md|Issue fin-ab3bc3ca2bf3d644]]
#### Observations
- [[occurrences/occ-e4ae272363a0d2fc.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e0695057e67d660.md|Issue fin-7e0695057e67d660]]
#### Observations
- [[occurrences/occ-8c5247bf72b91e1b.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-36b15950ea27fc6a.md|Issue fin-36b15950ea27fc6a]]
#### Observations
- [[occurrences/occ-b429b2b2cdc6d6d7.md|tagname]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cdfed40e59735ee6.md|Issue fin-cdfed40e59735ee6]]
#### Observations
- [[occurrences/occ-c1f8839e8e7bb6cf.md|third_party_scripts…ource_integrity.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-362081a3417b814e.md|Issue fin-362081a3417b814e]]
#### Observations
- [[occurrences/occ-30410ac02477546a.md|third_party_scripts…namically_added.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cb44a9463a904027.md|Issue fin-cb44a9463a904027]]
#### Observations
- [[occurrences/occ-9581ddd813ffdfe6.md|leakedinresource]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c5f73829347ff58.md|Issue fin-0c5f73829347ff58]]
#### Observations
- [[occurrences/occ-6aa11102f6c45b4a.md|mixedcontent]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-be4993e5526ca436.md|Issue fin-be4993e5526ca436]]
#### Observations
- [[occurrences/occ-4da29e2e32951ecb.md|mixedcontent/index.html]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a51b438416ff9cbf.md|Issue fin-a51b438416ff9cbf]]
#### Observations
- [[occurrences/occ-96738b2c4fc4d355.md|attribute_script]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-50435dcd1bfa39fd.md|Issue fin-50435dcd1bfa39fd]]
#### Observations
- [[occurrences/occ-2963645907f97474.md|js_assignment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9ba001252ad10a7f.md|Issue fin-9ba001252ad10a7f]]
#### Observations
- [[occurrences/occ-73feb989c93515ff.md|js_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-afadf0b70f3c2452.md|Issue fin-afadf0b70f3c2452]]
#### Observations
- [[occurrences/occ-da114b98a95fd54d.md|js_eval]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-76786462b0d5c122.md|Issue fin-76786462b0d5c122]]
#### Observations
- [[occurrences/occ-b6e10cb66a98fa7a.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0d47339d1b8d4cef.md|Issue fin-0d47339d1b8d4cef]]
#### Observations
- [[occurrences/occ-843e6199ca6b26a9.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7eb1086aa9aa2cf2.md|Issue fin-7eb1086aa9aa2cf2]]
#### Observations
- [[occurrences/occ-0b56b0b99a521776.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5fa42470b926ea22.md|Issue fin-5fa42470b926ea22]]
#### Observations
- [[occurrences/occ-971f1956fb5d9be0.md|noscript]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-09fbdccd754cfde2.md|Issue fin-09fbdccd754cfde2]]
#### Observations
- [[occurrences/occ-827154864586acdb.md|tagname]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3302c726cd1da891.md|Issue fin-3302c726cd1da891]]
#### Observations
- [[occurrences/occ-3ed26beed64284ec.md|script_src]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2645f594a0183458.md|Issue fin-2645f594a0183458]]
#### Observations
- [[occurrences/occ-e3fc4a54e3a863a4.md|object_hash.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-94da4e1e72c05956.md|Issue fin-94da4e1e72c05956]]
#### Observations
- [[occurrences/occ-aef0a9f35c0ce95f.md|script]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b770a7cbb4cd0ae0.md|Issue fin-b770a7cbb4cd0ae0]]
#### Observations
- [[occurrences/occ-8efc97376371ba43.md|script_hash.html]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-44897c74b3bc4731.md|Issue fin-44897c74b3bc4731]]
#### Observations
- [[occurrences/occ-ca255f5470526a73.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c852fcf92a55e61c.md|Issue fin-c852fcf92a55e61c]]
#### Observations
- [[occurrences/occ-562113c09d819017.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-04441e2c9aba4086.md|Issue fin-04441e2c9aba4086]]
#### Observations
- [[occurrences/occ-0d1656c90a8bba0b.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-86275782ae3dc59d.md|Issue fin-86275782ae3dc59d]]
#### Observations
- [[occurrences/occ-971dd22bda37c351.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_domain  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-46d39a96b3a76f9d.md|Issue fin-46d39a96b3a76f9d]]
#### Observations
- [[occurrences/occ-861acbfd8b96707c.md|script.src.partial_domain]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_query  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d693b53c497e61cb.md|Issue fin-d693b53c497e61cb]]
#### Observations
- [[occurrences/occ-912f5d5c3cb57cae.md|script.src.partial_query]]

### GET https://public-firing-range.appspot.com/urldom/location/search/area.href?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bd92523f4fcccdd4.md|Issue fin-bd92523f4fcccdd4]]
#### Observations
- [[occurrences/occ-0cd2731c9058d4e4.md|area.href]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc6871b836a6a6d0.md|Issue fin-fc6871b836a6a6d0]]
#### Observations
- [[occurrences/occ-ba2c5e042f718369.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-90ac77e56b333a2c.md|Issue fin-90ac77e56b333a2c]]
#### Observations
- [[occurrences/occ-9ad86597f5d25a5d.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/frame.src?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9f5ce1a0e7c655a1.md|Issue fin-9f5ce1a0e7c655a1]]
#### Observations
- [[occurrences/occ-0e49f2192ea0146c.md|frame.src]]

### GET https://public-firing-range.appspot.com/urldom/location/search/location.assign?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ecd67366e38153e5.md|Issue fin-ecd67366e38153e5]]
#### Observations
- [[occurrences/occ-a8a23a0b9e28c25a.md|location.assign]]

### GET https://public-firing-range.appspot.com/urldom/location/search/svg.a?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8e37b037cfaee295.md|Issue fin-8e37b037cfaee295]]
#### Observations
- [[occurrences/occ-25078106b1dfc585.md|svg.a]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db8b5a65f14d8657.md|Issue fin-db8b5a65f14d8657]]
#### Observations
- [[occurrences/occ-8de44838f299f333.md|jquery.html]]

