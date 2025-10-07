---
aliases:
  - "STS-0035"
cweId: "319"
cweUri: "https://cwe.mitre.org/data/definitions/319.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10035"
name: "Strict-Transport-Security Header Not Set"
occurrenceCount: "246"
pluginId: "10035"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "246"
wascId: "15"
---

# Strict-Transport-Security Header Not Set (Plugin 10035)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/StrictTransportSecurityScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/StrictTransportSecurityScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10035/

### How it detects

Passive; checks headers: Location; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- header:Location
- regex:\\bmax-age\\s*=\\s*\'*\
  - hint: Regular expression; see pattern for details.
- regex:\\bmax-age\\s*=\\s*\'*\
  - hint: Regular expression; see pattern for details.

## Remediation

Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.

### References
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- https://owasp.org/www-community/Security_Headers
- https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
- https://caniuse.com/stricttransportsecurity
- https://datatracker.ietf.org/doc/html/rfc6797

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e8000985f89e454.md|Issue fin-7e8000985f89e454]]
#### Observations
- [[occurrences/occ-15c539b210fb2e85.md|public-firing-range.appspot.com/]]

### GET https://public-firing-range.appspot.com/address/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ebfab9e615aad4d7.md|Issue fin-ebfab9e615aad4d7]]
#### Observations
- [[occurrences/occ-e7e19b846747ca9a.md|address]]

### GET https://public-firing-range.appspot.com/address/URL/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-721f11b6334e7fa7.md|Issue fin-721f11b6334e7fa7]]
#### Observations
- [[occurrences/occ-74194b5c219f2b1b.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/URLUnencoded/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4ae748e617c09c6f.md|Issue fin-4ae748e617c09c6f]]
#### Observations
- [[occurrences/occ-e36d33557c57bb0c.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/baseURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-33679564f2106b38.md|Issue fin-33679564f2106b38]]
#### Observations
- [[occurrences/occ-7c89bcc52db6c453.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/documentURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3a1d3642147a946e.md|Issue fin-3a1d3642147a946e]]
#### Observations
- [[occurrences/occ-11d512a9e4c2916c.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b31ff1b85dd11308.md|Issue fin-b31ff1b85dd11308]]
#### Observations
- [[occurrences/occ-85bc098d1e0487b4.md|address/index.html]]

### GET https://public-firing-range.appspot.com/address/location.hash/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-60c3091c902676dd.md|Issue fin-60c3091c902676dd]]
#### Observations
- [[occurrences/occ-49a1ac941e7e1129.md|assign]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f1a5e981c4b47044.md|Issue fin-f1a5e981c4b47044]]
#### Observations
- [[occurrences/occ-aa7015f7cf1fbb97.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1c78058ed54935d0.md|Issue fin-1c78058ed54935d0]]
#### Observations
- [[occurrences/occ-55c2bdf16db909d1.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a60b470aebba56e8.md|Issue fin-a60b470aebba56e8]]
#### Observations
- [[occurrences/occ-3d99e65cc9de1156.md|eval]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-145d2ec930627577.md|Issue fin-145d2ec930627577]]
#### Observations
- [[occurrences/occ-150ab8ed5d29ae63.md|formaction]]

### GET https://public-firing-range.appspot.com/address/location.hash/function  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f5d8a774b1340ded.md|Issue fin-f5d8a774b1340ded]]
#### Observations
- [[occurrences/occ-cb62a3437dd0d7b0.md|function]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-82234e6f0df912f0.md|Issue fin-82234e6f0df912f0]]
#### Observations
- [[occurrences/occ-619f77d822bfaf1e.md|inlineevent]]

### GET https://public-firing-range.appspot.com/address/location.hash/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dbdb5947660c4d20.md|Issue fin-dbdb5947660c4d20]]
#### Observations
- [[occurrences/occ-1934ebcee8573927.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location.hash/jshref  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6b2d3dae6c856644.md|Issue fin-6b2d3dae6c856644]]
#### Observations
- [[occurrences/occ-0533347c58e4f01a.md|jshref]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickAddEventListener  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fcb05aa7b925feb9.md|Issue fin-fcb05aa7b925feb9]]
#### Observations
- [[occurrences/occ-771fc5b049984e0e.md|onclickAddEventListener]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickSetAttribute  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4b30fa0bb1691bc5.md|Issue fin-4b30fa0bb1691bc5]]
#### Observations
- [[occurrences/occ-d2f5dbdcaa696747.md|onclickSetAttribute]]

### GET https://public-firing-range.appspot.com/address/location.hash/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5bec52f54ba542c2.md|Issue fin-5bec52f54ba542c2]]
#### Observations
- [[occurrences/occ-a839e3297d645871.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b9fc389a68b3ab75.md|Issue fin-b9fc389a68b3ab75]]
#### Observations
- [[occurrences/occ-9dcf20a7c850fd44.md|replace]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-969664f0db6248cb.md|Issue fin-969664f0db6248cb]]
#### Observations
- [[occurrences/occ-bdc32a7a87cb9799.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/location/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c486a6c86a292808.md|Issue fin-c486a6c86a292808]]
#### Observations
- [[occurrences/occ-45c7edc7fae4e38b.md|assign]]

### GET https://public-firing-range.appspot.com/address/location/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0e019a95175fd32d.md|Issue fin-0e019a95175fd32d]]
#### Observations
- [[occurrences/occ-3c4b2cc016b79d57.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-93ff6e8c2718d3f0.md|Issue fin-93ff6e8c2718d3f0]]
#### Observations
- [[occurrences/occ-f9dc63d4217c4a54.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a8f99356ff05621b.md|Issue fin-a8f99356ff05621b]]
#### Observations
- [[occurrences/occ-5f6281432a465ba8.md|eval]]

### GET https://public-firing-range.appspot.com/address/location/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9b7faa14a04994cf.md|Issue fin-9b7faa14a04994cf]]
#### Observations
- [[occurrences/occ-1561faf6145dd7ee.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d72158fd3b805027.md|Issue fin-d72158fd3b805027]]
#### Observations
- [[occurrences/occ-2e2aa089e3c58be6.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9d2a02bfdf15a793.md|Issue fin-9d2a02bfdf15a793]]
#### Observations
- [[occurrences/occ-6a1c5a0f281a911b.md|replace]]

### GET https://public-firing-range.appspot.com/address/location/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec5768005ac05b57.md|Issue fin-ec5768005ac05b57]]
#### Observations
- [[occurrences/occ-605c510ebe5cc716.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/locationhref/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5fbc081dbe45f1fa.md|Issue fin-5fbc081dbe45f1fa]]
#### Observations
- [[occurrences/occ-fc3fb3f1c3f09dc5.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationpathname/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b707c9ad09296b44.md|Issue fin-b707c9ad09296b44]]
#### Observations
- [[occurrences/occ-9b98eb879bf145c6.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationsearch/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2d01617d0716386c.md|Issue fin-2d01617d0716386c]]
#### Observations
- [[occurrences/occ-fd98bde081dba148.md|documentwrite]]

### GET https://public-firing-range.appspot.com/angular/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c9365cfa959796e2.md|Issue fin-c9365cfa959796e2]]
#### Observations
- [[occurrences/occ-69e14c23505b0230.md|angular]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b3790eaf37ed175.md|Issue fin-7b3790eaf37ed175]]
#### Observations
- [[occurrences/occ-6de2d3cbb1273d86.md|1.1.5]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ac90592c2b9bb3be.md|Issue fin-ac90592c2b9bb3be]]
#### Observations
- [[occurrences/occ-ea72b6109fe83340.md|1.2.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-186a7b138a5ddcc9.md|Issue fin-186a7b138a5ddcc9]]
#### Observations
- [[occurrences/occ-0d14105f2200d5fd.md|1.2.18]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2d1cc21e3aaebd81.md|Issue fin-2d1cc21e3aaebd81]]
#### Observations
- [[occurrences/occ-848013aa216d37f1.md|1.2.19]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a597d1d697c485be.md|Issue fin-a597d1d697c485be]]
#### Observations
- [[occurrences/occ-af7b586e9095e0fa.md|1.2.24]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1b6ee81138f4bf18.md|Issue fin-1b6ee81138f4bf18]]
#### Observations
- [[occurrences/occ-e599450eb92f382b.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3700dfa719695460.md|Issue fin-3700dfa719695460]]
#### Observations
- [[occurrences/occ-0b6cd5ef8a4fdfbd.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a76638e063ca3ef2.md|Issue fin-a76638e063ca3ef2]]
#### Observations
- [[occurrences/occ-9f151e302b22fce4.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e7a6c040ac276881.md|Issue fin-e7a6c040ac276881]]
#### Observations
- [[occurrences/occ-6e1c92ff8bd2a957.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4a79a88b2eb8827a.md|Issue fin-4a79a88b2eb8827a]]
#### Observations
- [[occurrences/occ-bd64299893f76649.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ff51f68d42c8970a.md|Issue fin-ff51f68d42c8970a]]
#### Observations
- [[occurrences/occ-488af3e1588732fe.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-abd46f1ec7fb27c6.md|Issue fin-abd46f1ec7fb27c6]]
#### Observations
- [[occurrences/occ-524d4e5be27ab64c.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5668d03a0245081d.md|Issue fin-5668d03a0245081d]]
#### Observations
- [[occurrences/occ-29e814b8def42c0d.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6ff0f345a43438ec.md|Issue fin-6ff0f345a43438ec]]
#### Observations
- [[occurrences/occ-702d4c5ec91331f8.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-716a96da079c5d3e.md|Issue fin-716a96da079c5d3e]]
#### Observations
- [[occurrences/occ-afca45bf99f18058.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-03d35fc551ba95f8.md|Issue fin-03d35fc551ba95f8]]
#### Observations
- [[occurrences/occ-97613b6ca810697b.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5036f9ac2fd0b8d6.md|Issue fin-5036f9ac2fd0b8d6]]
#### Observations
- [[occurrences/occ-835487b9d867acf2.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8fd944873773fbd3.md|Issue fin-8fd944873773fbd3]]
#### Observations
- [[occurrences/occ-879d23661ef42a82.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eba5435a96462414.md|Issue fin-eba5435a96462414]]
#### Observations
- [[occurrences/occ-97349fd4f0c17dfa.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-93d5eb402ca7c1af.md|Issue fin-93d5eb402ca7c1af]]
#### Observations
- [[occurrences/occ-102167d22e7bd593.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4193c627c6f0ef65.md|Issue fin-4193c627c6f0ef65]]
#### Observations
- [[occurrences/occ-34b5044f28dbf190.md|angular/index.html]]

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6877d8d208cf670b.md|Issue fin-6877d8d208cf670b]]
#### Observations
- [[occurrences/occ-756e7640a00c0f2e.md|badscriptimport]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-35dbf22c8d6a8501.md|Issue fin-35dbf22c8d6a8501]]
#### Observations
- [[occurrences/occ-f3e7cd2280f17a71.md|badscriptimport/index.html]]

### GET https://public-firing-range.appspot.com/clickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-da26dff1e6489ccf.md|Issue fin-da26dff1e6489ccf]]
#### Observations
- [[occurrences/occ-92f02a57b016422a.md|clickjacking]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_csp_no_frame_ancestors  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-726e52f7659a12b8.md|Issue fin-726e52f7659a12b8]]
#### Observations
- [[occurrences/occ-e6b6d6ed97925630.md|clickjacking_csp_no_frame_ancestors]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_xfo_allowall  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a671113adec68942.md|Issue fin-a671113adec68942]]
#### Observations
- [[occurrences/occ-a5478459869df792.md|clickjacking_xfo_allowall]]

### GET https://public-firing-range.appspot.com/clickjacking/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ebd061df59ff1151.md|Issue fin-ebd061df59ff1151]]
#### Observations
- [[occurrences/occ-1408a169875cf2b2.md|clickjacking/index.html]]

### GET https://public-firing-range.appspot.com/cors/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-afe8c168b15b4fea.md|Issue fin-afe8c168b15b4fea]]
#### Observations
- [[occurrences/occ-0c123e28156b20ab.md|cors]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowInsecureScheme  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9f02a79ba6e8875d.md|Issue fin-9f02a79ba6e8875d]]
#### Observations
- [[occurrences/occ-8fdc40cdd66d6247.md|allowInsecureScheme]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6709afc6edfffbce.md|Issue fin-6709afc6edfffbce]]
#### Observations
- [[occurrences/occ-b46350a670528ac4.md|allowNullOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8106f71ad9d716bb.md|Issue fin-8106f71ad9d716bb]]
#### Observations
- [[occurrences/occ-b9d8fbd5ecccf02d.md|allowNullOrigin]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c0aff9cd416e84d0.md|Issue fin-c0aff9cd416e84d0]]
#### Observations
- [[occurrences/occ-6f24061b9a2a2f78.md|allowOriginEndsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-34131450a94a3b2c.md|Issue fin-34131450a94a3b2c]]
#### Observations
- [[occurrences/occ-e70609f172272616.md|allowOriginEndsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginProtocolDowngrade  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d0eef299dac95583.md|Issue fin-d0eef299dac95583]]
#### Observations
- [[occurrences/occ-c0a2ae23755bc620.md|allowOriginProtocolDowngrade]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginRegexDot  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1d56856908efeed9.md|Issue fin-1d56856908efeed9]]
#### Observations
- [[occurrences/occ-f34a0668bea5f607.md|allowOriginRegexDot]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dba5cb2694fd3c64.md|Issue fin-dba5cb2694fd3c64]]
#### Observations
- [[occurrences/occ-b13cff32472ef927.md|allowOriginStartsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bc295b8ef46cc346.md|Issue fin-bc295b8ef46cc346]]
#### Observations
- [[occurrences/occ-8180073f1098a99a.md|allowOriginStartsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6efd95d969b8257b.md|Issue fin-6efd95d969b8257b]]
#### Observations
- [[occurrences/occ-c8f80069900f01b6.md|dynamicAllowOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3b20f83333082c00.md|Issue fin-3b20f83333082c00]]
#### Observations
- [[occurrences/occ-a41ae3700a21d514.md|dynamicAllowOrigin]]

### GET https://public-firing-range.appspot.com/cors/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6a00a0288ef94e5e.md|Issue fin-6a00a0288ef94e5e]]
#### Observations
- [[occurrences/occ-cdd4b0cb73729a0f.md|cors/index.html]]

### GET https://public-firing-range.appspot.com/dom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-01adbcb19432aeb2.md|Issue fin-01adbcb19432aeb2]]
#### Observations
- [[occurrences/occ-6ecad9436b633f2f.md|dom]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eedf81b84a7da48e.md|Issue fin-eedf81b84a7da48e]]
#### Observations
- [[occurrences/occ-87f4d0c0cad0846b.md|dompropagation]]

### GET https://public-firing-range.appspot.com/dom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-06d013cc43347a7f.md|Issue fin-06d013cc43347a7f]]
#### Observations
- [[occurrences/occ-c4de9d1af7bc78ff.md|dom/index.html]]

### GET https://public-firing-range.appspot.com/dom/javascripturi.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1f4a5f165eec0c3e.md|Issue fin-1f4a5f165eec0c3e]]
#### Observations
- [[occurrences/occ-94e767bd839d1a29.md|javascripturi.html]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9afecab219bfab90.md|Issue fin-9afecab219bfab90]]
#### Observations
- [[occurrences/occ-ea912890a9b05b42.md|complexMessageDocumentWriteEval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bd4e00486d830cb0.md|Issue fin-bd4e00486d830cb0]]
#### Observations
- [[occurrences/occ-9c3f465f34d570fa.md|documentWrite]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-69e0ed88cc563cc5.md|Issue fin-69e0ed88cc563cc5]]
#### Observations
- [[occurrences/occ-b9cb34a563cc7b18.md|eval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-49788a9c3d6367f6.md|Issue fin-49788a9c3d6367f6]]
#### Observations
- [[occurrences/occ-90fe8bb573ff1c85.md|improperOriginValid…tialStringComparison]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9a85c12b992d8988.md|Issue fin-9a85c12b992d8988]]
#### Observations
- [[occurrences/occ-685c616bfba023e7.md|improperOriginValidationWithRegExp]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e1a9e4628a7edcd2.md|Issue fin-e1a9e4628a7edcd2]]
#### Observations
- [[occurrences/occ-e8efe818453e8395.md|innerHtml]]

### GET https://public-firing-range.appspot.com/escape/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef7dda06990c66d1.md|Issue fin-ef7dda06990c66d1]]
#### Observations
- [[occurrences/occ-e6b39991fa88e229.md|escape]]

### GET https://public-firing-range.appspot.com/escape/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2acafd0b71bba854.md|Issue fin-2acafd0b71bba854]]
#### Observations
- [[occurrences/occ-98f5c93ae24b72af.md|escape/index.html]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-14295ee702a01863.md|Issue fin-14295ee702a01863]]
#### Observations
- [[occurrences/occ-6955df1acbf64759.md|encodeURIComponent]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b301419d1eb1111.md|Issue fin-8b301419d1eb1111]]
#### Observations
- [[occurrences/occ-651153b3b60e0c3c.md|escape]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9f82b935c6cea541.md|Issue fin-9f82b935c6cea541]]
#### Observations
- [[occurrences/occ-58e4a88769dcc2a7.md|html_escape]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d7c3491327d0e0a6.md|Issue fin-d7c3491327d0e0a6]]
#### Observations
- [[occurrences/occ-512e0a9b7460e195.md|a]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8d0ca818e73ba633.md|Issue fin-8d0ca818e73ba633]]
#### Observations
- [[occurrences/occ-790b10c92f0cd28f.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-60fbdb344d45d0dd.md|Issue fin-60fbdb344d45d0dd]]
#### Observations
- [[occurrences/occ-511a87305b799113.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-70223a3d6c91694f.md|Issue fin-70223a3d6c91694f]]
#### Observations
- [[occurrences/occ-e958e80277397baf.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6a3222e8f955e120.md|Issue fin-6a3222e8f955e120]]
#### Observations
- [[occurrences/occ-9fb80d2d2dbf478a.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-235b184700baf055.md|Issue fin-235b184700baf055]]
#### Observations
- [[occurrences/occ-3cdc9a2cf4732596.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-367b759096f8d100.md|Issue fin-367b759096f8d100]]
#### Observations
- [[occurrences/occ-c6f32fe9d23de2aa.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-337eaa880671eacf.md|Issue fin-337eaa880671eacf]]
#### Observations
- [[occurrences/occ-e469793b17e24d60.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cb467d273cc00a6b.md|Issue fin-cb467d273cc00a6b]]
#### Observations
- [[occurrences/occ-ef8aea3fbfc82cb3.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aa8ade67ec91809d.md|Issue fin-aa8ade67ec91809d]]
#### Observations
- [[occurrences/occ-70cd2dd34a7d53af.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-152ea45556b5d67b.md|Issue fin-152ea45556b5d67b]]
#### Observations
- [[occurrences/occ-3eae617d5e0d1591.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3d0d698af11563ce.md|Issue fin-3d0d698af11563ce]]
#### Observations
- [[occurrences/occ-c0e6cdb601ddf079.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-178e1cbc149b3829.md|Issue fin-178e1cbc149b3829]]
#### Observations
- [[occurrences/occ-1251f62e6a41371e.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0f895f8a96b6890f.md|Issue fin-0f895f8a96b6890f]]
#### Observations
- [[occurrences/occ-85ecb8d7d6b5fe49.md|href]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-759d19acbceaa5c3.md|Issue fin-759d19acbceaa5c3]]
#### Observations
- [[occurrences/occ-b346f5eaaba74ac6.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dc16916197b7658d.md|Issue fin-dc16916197b7658d]]
#### Observations
- [[occurrences/occ-c06f3aad4ab61c86.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6016e88353b2eb93.md|Issue fin-6016e88353b2eb93]]
#### Observations
- [[occurrences/occ-6e55e846f1c0ad9d.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b1766e2368230602.md|Issue fin-b1766e2368230602]]
#### Observations
- [[occurrences/occ-7d74b2fae04f2e9d.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-edeb8d253236d35d.md|Issue fin-edeb8d253236d35d]]
#### Observations
- [[occurrences/occ-9005a33cd0166f5a.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1051824516b1500d.md|Issue fin-1051824516b1500d]]
#### Observations
- [[occurrences/occ-cb1cb8bbd0705599.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b6e7e42584abdbc.md|Issue fin-7b6e7e42584abdbc]]
#### Observations
- [[occurrences/occ-0688c423cd367110.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6a47f489ded27e00.md|Issue fin-6a47f489ded27e00]]
#### Observations
- [[occurrences/occ-cf2b5dfcb94cf80b.md|textarea]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2832e9f7098cff28.md|Issue fin-2832e9f7098cff28]]
#### Observations
- [[occurrences/occ-d45378c9e9b43c21.md|a]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-62ba8a337b94cb01.md|Issue fin-62ba8a337b94cb01]]
#### Observations
- [[occurrences/occ-4b8521518d6e904d.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e3ebdc0b3f4d7e98.md|Issue fin-e3ebdc0b3f4d7e98]]
#### Observations
- [[occurrences/occ-1474178c6d43c502.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2d5c7c095a1f22c6.md|Issue fin-2d5c7c095a1f22c6]]
#### Observations
- [[occurrences/occ-b6927cffc376c504.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a800e337a4133bcc.md|Issue fin-a800e337a4133bcc]]
#### Observations
- [[occurrences/occ-500e1c0a0b52b5a8.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-23e6011d2d856fec.md|Issue fin-23e6011d2d856fec]]
#### Observations
- [[occurrences/occ-c3afa004958c539f.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b32db410e5a18bca.md|Issue fin-b32db410e5a18bca]]
#### Observations
- [[occurrences/occ-421870b5bc7fa7ef.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6722613cb80de820.md|Issue fin-6722613cb80de820]]
#### Observations
- [[occurrences/occ-c234808e3c18aae6.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9e4cc33e11cc6440.md|Issue fin-9e4cc33e11cc6440]]
#### Observations
- [[occurrences/occ-ec84e9f98a2f94c7.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-87c30e1fb18a4ffc.md|Issue fin-87c30e1fb18a4ffc]]
#### Observations
- [[occurrences/occ-be3ee22a6794e868.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e5e9b4ee472ce322.md|Issue fin-e5e9b4ee472ce322]]
#### Observations
- [[occurrences/occ-eeeec1053943eb60.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_value?q=a&escape=HTML_ESCAPE  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-691190abee4a326a.md|Issue fin-691190abee4a326a]]
#### Observations
- [[occurrences/occ-75e436ec134cc481.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-971924cc94f47df2.md|Issue fin-971924cc94f47df2]]
#### Observations
- [[occurrences/occ-c5c9bb0b88d04082.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5025303d3c9f7837.md|Issue fin-5025303d3c9f7837]]
#### Observations
- [[occurrences/occ-c08222651687eb6e.md|href]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fa930db6fdea59fe.md|Issue fin-fa930db6fdea59fe]]
#### Observations
- [[occurrences/occ-d01cb98bc53fd995.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-146bfc51123eafed.md|Issue fin-146bfc51123eafed]]
#### Observations
- [[occurrences/occ-bad25b58793250bd.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-76877f1651deef07.md|Issue fin-76877f1651deef07]]
#### Observations
- [[occurrences/occ-a19c030f08205fe3.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3d74d26614b6be34.md|Issue fin-3d74d26614b6be34]]
#### Observations
- [[occurrences/occ-90d43ccaf4e4c81a.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7006db8d4d18f2c8.md|Issue fin-7006db8d4d18f2c8]]
#### Observations
- [[occurrences/occ-5aaf462579707251.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-311e20e403a45900.md|Issue fin-311e20e403a45900]]
#### Observations
- [[occurrences/occ-dde9c57285d0777f.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-54c2ea59e37391c6.md|Issue fin-54c2ea59e37391c6]]
#### Observations
- [[occurrences/occ-3fd98cbbacfccd88.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c0f6ff9554523f9.md|Issue fin-0c0f6ff9554523f9]]
#### Observations
- [[occurrences/occ-7f45a6ddbcb3183c.md|textarea]]

### GET https://public-firing-range.appspot.com/favicon.ico  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-785203ccd03f1754.md|Issue fin-785203ccd03f1754]]
#### Observations
- [[occurrences/occ-3eca78310f307bc0.md|favicon.ico]]

### GET https://public-firing-range.appspot.com/flashinjection/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6ed3e464e72b9b7d.md|Issue fin-6ed3e464e72b9b7d]]
#### Observations
- [[occurrences/occ-6bb22287489420d1.md|flashinjection]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackIsEchoedBack?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3ba739ee9f575c3a.md|Issue fin-3ba739ee9f575c3a]]
#### Observations
- [[occurrences/occ-aaa4514ef99858d2.md|callbackIsEchoedBack]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackParameterDoesNothing?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4128e19005ad9ef3.md|Issue fin-4128e19005ad9ef3]]
#### Observations
- [[occurrences/occ-7f54eebc00548013.md|callbackParameterDoesNothing]]

### GET https://public-firing-range.appspot.com/flashinjection/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db51076c1d7c8e0a.md|Issue fin-db51076c1d7c8e0a]]
#### Observations
- [[occurrences/occ-52b2d6b4bbe6a105.md|flashinjection/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f5e05caa6324837.md|Issue fin-7f5e05caa6324837]]
#### Observations
- [[occurrences/occ-6135955d975521f8.md|insecurethirdpartyscripts]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-94d408bdca406f33.md|Issue fin-94d408bdca406f33]]
#### Observations
- [[occurrences/occ-c834373f79f05f9f.md|insecurethirdpartyscripts/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ab79b3bfd60b8fa.md|Issue fin-0ab79b3bfd60b8fa]]
#### Observations
- [[occurrences/occ-f5f414344009dcb7.md|third_party_scripts…ource_integrity.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4bd086328d0be8b1.md|Issue fin-4bd086328d0be8b1]]
#### Observations
- [[occurrences/occ-eb441e34ab1f6c0f.md|third_party_scripts…namically_added.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-46169f824e09885a.md|Issue fin-46169f824e09885a]]
#### Observations
- [[occurrences/occ-77ccce3e4299dc0f.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-685fbdb4ec77dfe5.md|Issue fin-685fbdb4ec77dfe5]]
#### Observations
- [[occurrences/occ-10fce66dbe4b7970.md|leakedcookie/index.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-59e677cd15623404.md|Issue fin-59e677cd15623404]]
#### Observations
- [[occurrences/occ-a5b7e7d0fa17debc.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b6f1099425f77fe4.md|Issue fin-b6f1099425f77fe4]]
#### Observations
- [[occurrences/occ-c3eb104a8a01f408.md|leakedinresource]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7841647b621a1192.md|Issue fin-7841647b621a1192]]
#### Observations
- [[occurrences/occ-a07c682e6bee52e1.md|mixedcontent]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3ad641f015cac8f4.md|Issue fin-3ad641f015cac8f4]]
#### Observations
- [[occurrences/occ-47d521193b65a5a2.md|mixedcontent/index.html]]

### GET https://public-firing-range.appspot.com/redirect/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ff20cf5b9b68c76b.md|Issue fin-ff20cf5b9b68c76b]]
#### Observations
- [[occurrences/occ-ef40cd2a25f2bb7f.md|redirect]]

### GET https://public-firing-range.appspot.com/redirect/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8a6b73b4b651f3c5.md|Issue fin-8a6b73b4b651f3c5]]
#### Observations
- [[occurrences/occ-92e924fc071ddd3f.md|redirect/index.html]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b1abfe17860b3c03.md|Issue fin-b1abfe17860b3c03]]
#### Observations
- [[occurrences/occ-66be891ea862eb40.md|meta]]

### GET https://public-firing-range.appspot.com/reflected/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-17cad4a4fd324d4d.md|Issue fin-17cad4a4fd324d4d]]
#### Observations
- [[occurrences/occ-8882bc2a2cf42408.md|reflected]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8eea082532af328b.md|Issue fin-8eea082532af328b]]
#### Observations
- [[occurrences/occ-1ee7d434f3e57edc.md|json]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/plaintext?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-488f8f53f7f29d6e.md|Issue fin-488f8f53f7f29d6e]]
#### Observations
- [[occurrences/occ-b65fa212d871464b.md|plaintext]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4d520b6d349ad779.md|Issue fin-4d520b6d349ad779]]
#### Observations
- [[occurrences/occ-1508412f91592bb0.md|DOUBLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4f78248473937627.md|Issue fin-4f78248473937627]]
#### Observations
- [[occurrences/occ-6a278f069cfd5dbd.md|SINGLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7014af192a9b4853.md|Issue fin-7014af192a9b4853]]
#### Observations
- [[occurrences/occ-9341df7d004c91ac.md|UNQUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e15b67d23de93067.md|Issue fin-e15b67d23de93067]]
#### Observations
- [[occurrences/occ-448090e4db98573c.md|DoubleQuoteSinglequote]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d5c9a460731cdbbb.md|Issue fin-d5c9a460731cdbbb]]
#### Observations
- [[occurrences/occ-160657c9f1c281d0.md|SpaceDoubleQuoteSlashEquals]]

### GET https://public-firing-range.appspot.com/reflected/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-390844cb8753d41c.md|Issue fin-390844cb8753d41c]]
#### Observations
- [[occurrences/occ-a0d10e0cd1f75073.md|reflected/index.html]]

### GET https://public-firing-range.appspot.com/reflected/jsoncallback  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-84086c43441e37be.md|Issue fin-84086c43441e37be]]
#### Observations
- [[occurrences/occ-906a26bbd8187a26.md|jsoncallback]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee925050d513bafe.md|Issue fin-ee925050d513bafe]]
#### Observations
- [[occurrences/occ-b806aadcafbdd7e4.md|attribute_name]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-38b5d188fba07a40.md|Issue fin-38b5d188fba07a40]]
#### Observations
- [[occurrences/occ-3e0f83dcb601aaed.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d5c554ccfa507046.md|Issue fin-d5c554ccfa507046]]
#### Observations
- [[occurrences/occ-e8449b3ade0d818b.md|attribute_script]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-81b73434bbbc2732.md|Issue fin-81b73434bbbc2732]]
#### Observations
- [[occurrences/occ-f06250b80345590b.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8860ee7b43dc3532.md|Issue fin-8860ee7b43dc3532]]
#### Observations
- [[occurrences/occ-3ce4b5e1ab2b24a0.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/400?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b73f302583e8708d.md|Issue fin-b73f302583e8708d]]
#### Observations
- [[occurrences/occ-07b4309902ebbd63.md|400]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/401?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-89341f31784d3105.md|Issue fin-89341f31784d3105]]
#### Observations
- [[occurrences/occ-b75b4822917a61ab.md|401]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/403?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6f01c70fa631a23a.md|Issue fin-6f01c70fa631a23a]]
#### Observations
- [[occurrences/occ-c14dc7196719d233.md|403]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/404?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1d30466bc4599e08.md|Issue fin-1d30466bc4599e08]]
#### Observations
- [[occurrences/occ-a67b17ab312d8f3d.md|404]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/500?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-011fb18cd8e83d10.md|Issue fin-011fb18cd8e83d10]]
#### Observations
- [[occurrences/occ-cf92c6e88a89ef95.md|500]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4d0ed8cd22cc1bfa.md|Issue fin-4d0ed8cd22cc1bfa]]
#### Observations
- [[occurrences/occ-51b7bd01ea60dc22.md|body]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2644c15ddd6ea77c.md|Issue fin-2644c15ddd6ea77c]]
#### Observations
- [[occurrences/occ-eac8a14b57ebdd3a.md|body_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f14bc58d75290b92.md|Issue fin-f14bc58d75290b92]]
#### Observations
- [[occurrences/occ-150382d1e499b08b.md|css_style]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0fb6ccbc92fc1c26.md|Issue fin-0fb6ccbc92fc1c26]]
#### Observations
- [[occurrences/occ-25c88086c3e31b1e.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3205c9483eb42eb7.md|Issue fin-3205c9483eb42eb7]]
#### Observations
- [[occurrences/occ-6942b18ab9e27c88.md|css_style_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/form  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9fc68f54017f1e8f.md|Issue fin-9fc68f54017f1e8f]]
#### Observations
- [[occurrences/occ-f0df89c5ed78ca54.md|form]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1ed3c76990729d20.md|Issue fin-1ed3c76990729d20]]
#### Observations
- [[occurrences/occ-bbe4392a5f0a2fc1.md|head]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eeaa3f6f71e544df.md|Issue fin-eeaa3f6f71e544df]]
#### Observations
- [[occurrences/occ-5499bde7810dc419.md|iframe_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5c806d4b8b5993aa.md|Issue fin-5c806d4b8b5993aa]]
#### Observations
- [[occurrences/occ-796b299821efcea2.md|iframe_srcdoc]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce835824ccd98058.md|Issue fin-ce835824ccd98058]]
#### Observations
- [[occurrences/occ-a843efac810fbd19.md|js_assignment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec71dfe6dc380348.md|Issue fin-ec71dfe6dc380348]]
#### Observations
- [[occurrences/occ-39548dd0af0725b2.md|js_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-884aeb87c2fc1bcf.md|Issue fin-884aeb87c2fc1bcf]]
#### Observations
- [[occurrences/occ-82c561d6a38b3313.md|js_eval]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-290a1b30514e8840.md|Issue fin-290a1b30514e8840]]
#### Observations
- [[occurrences/occ-da7252690a36ae90.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-615123ceaa2a7e41.md|Issue fin-615123ceaa2a7e41]]
#### Observations
- [[occurrences/occ-a68b2cde25e57f93.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4d88ea097b6f0f11.md|Issue fin-4d88ea097b6f0f11]]
#### Observations
- [[occurrences/occ-6d0d1d6f36728a6b.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-648ab22667edd5a4.md|Issue fin-648ab22667edd5a4]]
#### Observations
- [[occurrences/occ-e071a7d1e3fccc1a.md|json]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e7dbc45233705756.md|Issue fin-e7dbc45233705756]]
#### Observations
- [[occurrences/occ-550858128b20524e.md|noscript]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db1dc8c4aa308686.md|Issue fin-db1dc8c4aa308686]]
#### Observations
- [[occurrences/occ-42b4694b11e0edd2.md|style_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eab5dce64f07c190.md|Issue fin-eab5dce64f07c190]]
#### Observations
- [[occurrences/occ-70ed36fc429e1f1e.md|tagname]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-21d56a3512acd8ef.md|Issue fin-21d56a3512acd8ef]]
#### Observations
- [[occurrences/occ-08999487a4738355.md|textarea]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c5f1092d6f6b6a60.md|Issue fin-c5f1092d6f6b6a60]]
#### Observations
- [[occurrences/occ-e98f114de073b540.md|textarea_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-68c6f12635e6d3bc.md|Issue fin-68c6f12635e6d3bc]]
#### Observations
- [[occurrences/occ-076ceeaa1633e8f8.md|title]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0056db4546f36514.md|Issue fin-0056db4546f36514]]
#### Observations
- [[occurrences/occ-d133f44ea442d46e.md|css_import]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3140c000613d6019.md|Issue fin-3140c000613d6019]]
#### Observations
- [[occurrences/occ-cb0d25511dfdb31f.md|href]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7c358a1fd8575d4d.md|Issue fin-7c358a1fd8575d4d]]
#### Observations
- [[occurrences/occ-a85874f85414214c.md|object_data]]

### GET https://public-firing-range.appspot.com/reflected/url/object_param?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f07a89f058afcebd.md|Issue fin-f07a89f058afcebd]]
#### Observations
- [[occurrences/occ-17c8214227603941.md|object_param]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bee750ccab47262c.md|Issue fin-bee750ccab47262c]]
#### Observations
- [[occurrences/occ-cc0593f75ae56af7.md|script_src]]

### GET https://public-firing-range.appspot.com/remoteinclude/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f551b2b435af09b0.md|Issue fin-f551b2b435af09b0]]
#### Observations
- [[occurrences/occ-e5a579b8dd315474.md|remoteinclude]]

### GET https://public-firing-range.appspot.com/remoteinclude/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5441a8f833b946ba.md|Issue fin-5441a8f833b946ba]]
#### Observations
- [[occurrences/occ-11f8c2b0d1474690.md|remoteinclude/index.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-161585387e6a9ee2.md|Issue fin-161585387e6a9ee2]]
#### Observations
- [[occurrences/occ-52d2d30bce293e1a.md|object_hash.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-41e695543c586446.md|Issue fin-41e695543c586446]]
#### Observations
- [[occurrences/occ-ca31ac6f86db04e4.md|application_x-shockwave-flash]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5bf01c318c136739.md|Issue fin-5bf01c318c136739]]
#### Observations
- [[occurrences/occ-b8e5b85f9c3b28ba.md|object_raw]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dcbe9ac446350dbc.md|Issue fin-dcbe9ac446350dbc]]
#### Observations
- [[occurrences/occ-cf8efcaec86ea353.md|script]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b130f296c80f733.md|Issue fin-8b130f296c80f733]]
#### Observations
- [[occurrences/occ-9453d4c85f722d77.md|script_hash.html]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1fe194daafe5c359.md|Issue fin-1fe194daafe5c359]]
#### Observations
- [[occurrences/occ-9d3a677990bd2d74.md|reverseclickjacking]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-61d2da7c8c72ed1d.md|Issue fin-61d2da7c8c72ed1d]]
#### Observations
- [[occurrences/occ-0704e58e535351cc.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ff8df7cc11a512dc.md|Issue fin-ff8df7cc11a512dc]]
#### Observations
- [[occurrences/occ-caca9f1f6924b7e2.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b6c6e267e0ebc0f.md|Issue fin-7b6c6e267e0ebc0f]]
#### Observations
- [[occurrences/occ-955cf12117454783.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dcd1ab78f65329ae.md|Issue fin-dcd1ab78f65329ae]]
#### Observations
- [[occurrences/occ-785396fd874e4cd8.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a4faa3bd2e0128a2.md|Issue fin-a4faa3bd2e0128a2]]
#### Observations
- [[occurrences/occ-b6c9fbcfc7ba053c.md|stricttransportsecurity]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-269e0ce49f53245c.md|Issue fin-269e0ce49f53245c]]
#### Observations
- [[occurrences/occ-b762357d39ce98e6.md|hsts_max_age_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fa9df6727c91307a.md|Issue fin-fa9df6727c91307a]]
#### Observations
- [[occurrences/occ-9e587e353f6f486d.md|hsts_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fce6b60bbb937149.md|Issue fin-fce6b60bbb937149]]
#### Observations
- [[occurrences/occ-16f775bc38379409.md|stricttransportsecurity/index.html]]

### GET https://public-firing-range.appspot.com/tags/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-66dd7114d0eb3853.md|Issue fin-66dd7114d0eb3853]]
#### Observations
- [[occurrences/occ-6a8da37c22ff2ceb.md|tags]]

### GET https://public-firing-range.appspot.com/tags/expression?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-46a9943f680749fc.md|Issue fin-46a9943f680749fc]]
#### Observations
- [[occurrences/occ-30627439f972745e.md|expression]]

### GET https://public-firing-range.appspot.com/tags/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-550b96dfe1313a66.md|Issue fin-550b96dfe1313a66]]
#### Observations
- [[occurrences/occ-81e133a9b20579d6.md|tags/index.html]]

### GET https://public-firing-range.appspot.com/tags/multiline?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bc63c51e328584a3.md|Issue fin-bc63c51e328584a3]]
#### Observations
- [[occurrences/occ-62d3788c4a1ee281.md|multiline]]

### GET https://public-firing-range.appspot.com/tags/tag/a/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8787c97423d0ae89.md|Issue fin-8787c97423d0ae89]]
#### Observations
- [[occurrences/occ-7fd8a618dd81161f.md|href]]

### GET https://public-firing-range.appspot.com/tags/tag/a/style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e751dfc3bfffd84.md|Issue fin-7e751dfc3bfffd84]]
#### Observations
- [[occurrences/occ-3dadf6115b575054.md|style]]

### GET https://public-firing-range.appspot.com/tags/tag/body/onload?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4af84fb359942cf8.md|Issue fin-4af84fb359942cf8]]
#### Observations
- [[occurrences/occ-22f87216628eb10c.md|onload]]

### GET https://public-firing-range.appspot.com/tags/tag/div/style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-40e53a9ecb662cb2.md|Issue fin-40e53a9ecb662cb2]]
#### Observations
- [[occurrences/occ-0f58d655f4dedb7c.md|style]]

### GET https://public-firing-range.appspot.com/tags/tag/div?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4575f176d4d6acf0.md|Issue fin-4575f176d4d6acf0]]
#### Observations
- [[occurrences/occ-a5cf8cbab57e5511.md|div]]

### GET https://public-firing-range.appspot.com/tags/tag/iframe?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4e1f2484534dc986.md|Issue fin-4e1f2484534dc986]]
#### Observations
- [[occurrences/occ-ec28707cfad80860.md|iframe]]

### GET https://public-firing-range.appspot.com/tags/tag/img?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ac35ab6e44c33877.md|Issue fin-ac35ab6e44c33877]]
#### Observations
- [[occurrences/occ-4c05d1a125639ec2.md|img]]

### GET https://public-firing-range.appspot.com/tags/tag/meta?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c8e8026abc0cb022.md|Issue fin-c8e8026abc0cb022]]
#### Observations
- [[occurrences/occ-75fcc85ca2f4a9e1.md|meta]]

### GET https://public-firing-range.appspot.com/tags/tag/script/src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eb6ad71e80e2fcec.md|Issue fin-eb6ad71e80e2fcec]]
#### Observations
- [[occurrences/occ-6bcf347b12683041.md|src]]

### GET https://public-firing-range.appspot.com/tags/tag/style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2c52053f7ed48853.md|Issue fin-2c52053f7ed48853]]
#### Observations
- [[occurrences/occ-10a1a26a78d7a9cf.md|style]]

### GET https://public-firing-range.appspot.com/tags/tag?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9f8a8df60331202b.md|Issue fin-9f8a8df60331202b]]
#### Observations
- [[occurrences/occ-376525f17cb20138.md|tag]]

### GET https://public-firing-range.appspot.com/urldom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ef90d3255d82f26.md|Issue fin-0ef90d3255d82f26]]
#### Observations
- [[occurrences/occ-2b8a8249f73949cb.md|urldom]]

### GET https://public-firing-range.appspot.com/urldom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-11ac129c0451d287.md|Issue fin-11ac129c0451d287]]
#### Observations
- [[occurrences/occ-b63bed92e584b294.md|urldom/index.html]]

### GET https://public-firing-range.appspot.com/urldom/jsonp?callback=foo  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-13701e5dd753129b.md|Issue fin-13701e5dd753129b]]
#### Observations
- [[occurrences/occ-f23fcded9f625b03.md|jsonp]]

### GET https://public-firing-range.appspot.com/urldom/jsonp?callback=foobar  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-76a2c4fdb5b02cf1.md|Issue fin-76a2c4fdb5b02cf1]]
#### Observations
- [[occurrences/occ-a118db7e63e29971.md|jsonp]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_domain  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cf9fc20d5a18947f.md|Issue fin-cf9fc20d5a18947f]]
#### Observations
- [[occurrences/occ-063189ee419fa61e.md|script.src.partial_domain]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_query  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fa37300522790e5e.md|Issue fin-fa37300522790e5e]]
#### Observations
- [[occurrences/occ-18a91d89034690d3.md|script.src.partial_query]]

### GET https://public-firing-range.appspot.com/urldom/location/search/area.href?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b33747deaad745fa.md|Issue fin-b33747deaad745fa]]
#### Observations
- [[occurrences/occ-18ac2a37c24628c2.md|area.href]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee728a1d05637cfc.md|Issue fin-ee728a1d05637cfc]]
#### Observations
- [[occurrences/occ-ba3d5283fc6e6225.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-871fd14a89e06d99.md|Issue fin-871fd14a89e06d99]]
#### Observations
- [[occurrences/occ-ed32b1848fae05c8.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/frame.src?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-be882e16d51f121b.md|Issue fin-be882e16d51f121b]]
#### Observations
- [[occurrences/occ-0dd533e7323e0b56.md|frame.src]]

### GET https://public-firing-range.appspot.com/urldom/location/search/location.assign?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b38ff97958af09f.md|Issue fin-8b38ff97958af09f]]
#### Observations
- [[occurrences/occ-13036949b7a59594.md|location.assign]]

### GET https://public-firing-range.appspot.com/urldom/location/search/svg.a?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3621b8dad9469c45.md|Issue fin-3621b8dad9469c45]]
#### Observations
- [[occurrences/occ-5f111bb290e76158.md|svg.a]]

### GET https://public-firing-range.appspot.com/urldom/redirect?url=http://example.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5abe67526104b89f.md|Issue fin-5abe67526104b89f]]
#### Observations
- [[occurrences/occ-2adec5594e31c84e.md|redirect]]

### GET https://public-firing-range.appspot.com/urldom/script.js  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b90a876ee1cc198b.md|Issue fin-b90a876ee1cc198b]]
#### Observations
- [[occurrences/occ-a6253d005716f5fb.md|script.js]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-63c447cf473fa586.md|Issue fin-63c447cf473fa586]]
#### Observations
- [[occurrences/occ-fb325d06321afcf3.md|vulnerablelibraries]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b72528108730f562.md|Issue fin-b72528108730f562]]
#### Observations
- [[occurrences/occ-5846afe47598ddc7.md|vulnerablelibraries/index.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-96bbcde1308ff99c.md|Issue fin-96bbcde1308ff99c]]
#### Observations
- [[occurrences/occ-ff6649446b9e4fbd.md|jquery.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/x  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cbdd58efb64e6bc5.md|Issue fin-cbdd58efb64e6bc5]]
#### Observations
- [[occurrences/occ-b30a866bed53d628.md|x]]

