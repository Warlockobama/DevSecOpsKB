---
aliases:
  - "HCAVH-0047"
cweId: "311"
cweUri: "https://cwe.mitre.org/data/definitions/311.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10047"
name: "HTTPS Content Available via HTTP"
occurrenceCount: "246"
pluginId: "10047"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "246"
wascId: "4"
---

# HTTPS Content Available via HTTP (Plugin 10047)

## Detection logic

- Logic: passive
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/HttpsAsHttpScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/HttpsAsHttpScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10047/

### How it detects

Passive; sets evidence

## Remediation

Ensure that your web server, application server, load balancer, etc. is configured to only serve such content via HTTPS. Consider implementing HTTP Strict Transport Security.

### References
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- https://owasp.org/www-community/Security_Headers
- https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
- https://caniuse.com/stricttransportsecurity
- https://datatracker.ietf.org/doc/html/rfc6797

## Issues

### GET https://public-firing-range.appspot.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7211ac66f10df759.md|Issue fin-7211ac66f10df759]]
#### Observations
- [[occurrences/occ-0a99681d51915a46.md|public-firing-range.appspot.com/]]

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-663b69fbdf80383d.md|Issue fin-663b69fbdf80383d]]
#### Observations
- [[occurrences/occ-3d8936dbd0ec3562.md|public-firing-range.appspot.com/]]

### GET https://public-firing-range.appspot.com/address  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1a07d15922bd7ebb.md|Issue fin-1a07d15922bd7ebb]]
#### Observations
- [[occurrences/occ-e0582f5fbc101b23.md|address]]

### GET https://public-firing-range.appspot.com/address/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-266a25d86011f864.md|Issue fin-266a25d86011f864]]
#### Observations
- [[occurrences/occ-a1df7329aab46c3b.md|address]]

### GET https://public-firing-range.appspot.com/address/URL/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-107a9ab1f86855fd.md|Issue fin-107a9ab1f86855fd]]
#### Observations
- [[occurrences/occ-a9be9dd4a3b03b65.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/URLUnencoded/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7fb80da46202301a.md|Issue fin-7fb80da46202301a]]
#### Observations
- [[occurrences/occ-f0e8a59bf3820015.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/baseURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ac0bda85c1e08b82.md|Issue fin-ac0bda85c1e08b82]]
#### Observations
- [[occurrences/occ-fa443831f8705667.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/documentURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2af7098b98e21139.md|Issue fin-2af7098b98e21139]]
#### Observations
- [[occurrences/occ-74c6ef4b30cd205b.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e40627325ba3b553.md|Issue fin-e40627325ba3b553]]
#### Observations
- [[occurrences/occ-de28d3731225fb41.md|address/index.html]]

### GET https://public-firing-range.appspot.com/address/location.hash/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1cba6252cc8d3954.md|Issue fin-1cba6252cc8d3954]]
#### Observations
- [[occurrences/occ-1dd627a05e7a8ee2.md|assign]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3801dad3b0e008e0.md|Issue fin-3801dad3b0e008e0]]
#### Observations
- [[occurrences/occ-902f2daf0f37ef27.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-454a856c40ab8a3d.md|Issue fin-454a856c40ab8a3d]]
#### Observations
- [[occurrences/occ-d8958d825fb382cc.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d49c2aba21432289.md|Issue fin-d49c2aba21432289]]
#### Observations
- [[occurrences/occ-b5dd5d8f73618b44.md|eval]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-835d288b7acecd2e.md|Issue fin-835d288b7acecd2e]]
#### Observations
- [[occurrences/occ-a7d964482ce28e64.md|formaction]]

### GET https://public-firing-range.appspot.com/address/location.hash/function  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7d5d86142f310194.md|Issue fin-7d5d86142f310194]]
#### Observations
- [[occurrences/occ-32dedebb311c47db.md|function]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6fb44fa4a6a288ec.md|Issue fin-6fb44fa4a6a288ec]]
#### Observations
- [[occurrences/occ-cb36e1df1273f526.md|inlineevent]]

### GET https://public-firing-range.appspot.com/address/location.hash/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b432d0bbf33bb0af.md|Issue fin-b432d0bbf33bb0af]]
#### Observations
- [[occurrences/occ-f99da7094c9886ef.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location.hash/jshref  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-965b6f5661ce0e6d.md|Issue fin-965b6f5661ce0e6d]]
#### Observations
- [[occurrences/occ-62f5cb2a63977f15.md|jshref]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickAddEventListener  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0601c71903137c77.md|Issue fin-0601c71903137c77]]
#### Observations
- [[occurrences/occ-70eb0fc0de288e6b.md|onclickAddEventListener]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickSetAttribute  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-803ff1852b770d2d.md|Issue fin-803ff1852b770d2d]]
#### Observations
- [[occurrences/occ-37eeb867a94b77dd.md|onclickSetAttribute]]

### GET https://public-firing-range.appspot.com/address/location.hash/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-79d8a36d0524b12f.md|Issue fin-79d8a36d0524b12f]]
#### Observations
- [[occurrences/occ-ce89f01995603d22.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-64c210b276c46b14.md|Issue fin-64c210b276c46b14]]
#### Observations
- [[occurrences/occ-5efa8ca6d7dd28b2.md|replace]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-647475406df5ac20.md|Issue fin-647475406df5ac20]]
#### Observations
- [[occurrences/occ-b21679a0362ed96b.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/location/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0aa4c2ed31f429b2.md|Issue fin-0aa4c2ed31f429b2]]
#### Observations
- [[occurrences/occ-52c61fca2db10636.md|assign]]

### GET https://public-firing-range.appspot.com/address/location/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a97e64ae759ec3ef.md|Issue fin-a97e64ae759ec3ef]]
#### Observations
- [[occurrences/occ-4cced8071ef93ffb.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d1a1bb7cc97d4515.md|Issue fin-d1a1bb7cc97d4515]]
#### Observations
- [[occurrences/occ-6d02864dbba996c4.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c6d778338358ae24.md|Issue fin-c6d778338358ae24]]
#### Observations
- [[occurrences/occ-10595338300fd7ad.md|eval]]

### GET https://public-firing-range.appspot.com/address/location/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f73eac362bdd5c58.md|Issue fin-f73eac362bdd5c58]]
#### Observations
- [[occurrences/occ-59103b2465bd8c2c.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9a1c9060309d8702.md|Issue fin-9a1c9060309d8702]]
#### Observations
- [[occurrences/occ-d4a0aa67eff5273a.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c234b3ec18586091.md|Issue fin-c234b3ec18586091]]
#### Observations
- [[occurrences/occ-abc69f90c06b06e4.md|replace]]

### GET https://public-firing-range.appspot.com/address/location/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-61dab0ae9700fea9.md|Issue fin-61dab0ae9700fea9]]
#### Observations
- [[occurrences/occ-ec8b6bbaaa6a4e36.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/locationhref/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-237b9f8298cada23.md|Issue fin-237b9f8298cada23]]
#### Observations
- [[occurrences/occ-adbed4898f79ff20.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationpathname/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2cd3bce7f7beb11c.md|Issue fin-2cd3bce7f7beb11c]]
#### Observations
- [[occurrences/occ-1f4f9e3c2dfdf264.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationsearch/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9beb06a5f2763999.md|Issue fin-9beb06a5f2763999]]
#### Observations
- [[occurrences/occ-118488befad78530.md|documentwrite]]

### GET https://public-firing-range.appspot.com/angular  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-067c99eb4ce7c8d2.md|Issue fin-067c99eb4ce7c8d2]]
#### Observations
- [[occurrences/occ-adf2d4fd8c7fea21.md|angular]]

### GET https://public-firing-range.appspot.com/angular/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0851d7fb0f7875c3.md|Issue fin-0851d7fb0f7875c3]]
#### Observations
- [[occurrences/occ-7156663ad8c7f16e.md|angular]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f967bdefca932c74.md|Issue fin-f967bdefca932c74]]
#### Observations
- [[occurrences/occ-82a64ab404895dad.md|1.1.5]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f88ce12024adeaed.md|Issue fin-f88ce12024adeaed]]
#### Observations
- [[occurrences/occ-ca8e5eabb776319c.md|1.2.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-75d23091d1d96621.md|Issue fin-75d23091d1d96621]]
#### Observations
- [[occurrences/occ-dc30122a6be75554.md|1.2.18]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2607f9f35dc6c720.md|Issue fin-2607f9f35dc6c720]]
#### Observations
- [[occurrences/occ-0f086f6afaaf6b27.md|1.2.19]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc9ddeef720969e2.md|Issue fin-fc9ddeef720969e2]]
#### Observations
- [[occurrences/occ-2d6ab12fbe6aaec4.md|1.2.24]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f58872a66fae8ce1.md|Issue fin-f58872a66fae8ce1]]
#### Observations
- [[occurrences/occ-afc1709f33afe60a.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce7a436fb0bde3bf.md|Issue fin-ce7a436fb0bde3bf]]
#### Observations
- [[occurrences/occ-20d21d5265c4f984.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-96572d765a2977c9.md|Issue fin-96572d765a2977c9]]
#### Observations
- [[occurrences/occ-c82795822a4d1365.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-65a5ea4d2d808211.md|Issue fin-65a5ea4d2d808211]]
#### Observations
- [[occurrences/occ-6a922695dcf86b8c.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e64c1542cec622fc.md|Issue fin-e64c1542cec622fc]]
#### Observations
- [[occurrences/occ-e5b9cb967a4de838.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-83561b67b6784078.md|Issue fin-83561b67b6784078]]
#### Observations
- [[occurrences/occ-29f1488cbb23a755.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c541c91985d6d3e0.md|Issue fin-c541c91985d6d3e0]]
#### Observations
- [[occurrences/occ-ea9638387768d54c.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ca9fa4721f0705fd.md|Issue fin-ca9fa4721f0705fd]]
#### Observations
- [[occurrences/occ-92ff60a3f34d36c7.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a477ffd39b573bde.md|Issue fin-a477ffd39b573bde]]
#### Observations
- [[occurrences/occ-48c21be36e2cf3ac.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-76966c4d1f2ed7f8.md|Issue fin-76966c4d1f2ed7f8]]
#### Observations
- [[occurrences/occ-205af5d35a85df96.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-600cb4a37dbe6ff4.md|Issue fin-600cb4a37dbe6ff4]]
#### Observations
- [[occurrences/occ-332b3dc5c793165c.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e01cca5b16b14b2.md|Issue fin-7e01cca5b16b14b2]]
#### Observations
- [[occurrences/occ-f1f3a3464f36373b.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-13be77e63ef56e6c.md|Issue fin-13be77e63ef56e6c]]
#### Observations
- [[occurrences/occ-63362749759a3f01.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f37524b44f0c4574.md|Issue fin-f37524b44f0c4574]]
#### Observations
- [[occurrences/occ-45ee1ffbec094344.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-573316d5fc45cc3d.md|Issue fin-573316d5fc45cc3d]]
#### Observations
- [[occurrences/occ-7e6f55a9a99671c4.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-14a525f246575c78.md|Issue fin-14a525f246575c78]]
#### Observations
- [[occurrences/occ-5e04568d578857ba.md|angular/index.html]]

### GET https://public-firing-range.appspot.com/badscriptimport  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-42d82468cd4b238f.md|Issue fin-42d82468cd4b238f]]
#### Observations
- [[occurrences/occ-a606b83d515d31f9.md|badscriptimport]]

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7dc0bd2b79f04016.md|Issue fin-7dc0bd2b79f04016]]
#### Observations
- [[occurrences/occ-64a076ff139a8de9.md|badscriptimport]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8f05b055439ca9c1.md|Issue fin-8f05b055439ca9c1]]
#### Observations
- [[occurrences/occ-9d59fb87a0fb51c7.md|badscriptimport/index.html]]

### GET https://public-firing-range.appspot.com/clickjacking  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f39d25d604dbcabf.md|Issue fin-f39d25d604dbcabf]]
#### Observations
- [[occurrences/occ-7821f551a6673316.md|clickjacking]]

### GET https://public-firing-range.appspot.com/clickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eeee21d134f7f526.md|Issue fin-eeee21d134f7f526]]
#### Observations
- [[occurrences/occ-98e9b8511009b4ec.md|clickjacking]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_csp_no_frame_ancestors  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-444e76a279065998.md|Issue fin-444e76a279065998]]
#### Observations
- [[occurrences/occ-244d16e4d090cd37.md|clickjacking_csp_no_frame_ancestors]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_xfo_allowall  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b326079a6ccf01fb.md|Issue fin-b326079a6ccf01fb]]
#### Observations
- [[occurrences/occ-4b65185270e6ff1d.md|clickjacking_xfo_allowall]]

### GET https://public-firing-range.appspot.com/clickjacking/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f16b9f0c8d82fa42.md|Issue fin-f16b9f0c8d82fa42]]
#### Observations
- [[occurrences/occ-4fb2e0bfbd868510.md|clickjacking/index.html]]

### GET https://public-firing-range.appspot.com/cors  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f80af2a4dbfbeb4c.md|Issue fin-f80af2a4dbfbeb4c]]
#### Observations
- [[occurrences/occ-afb52272c4567f3c.md|cors]]

### GET https://public-firing-range.appspot.com/cors/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-44a983c0cfbddc51.md|Issue fin-44a983c0cfbddc51]]
#### Observations
- [[occurrences/occ-3277d61082aeb8a5.md|cors]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowInsecureScheme  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e07debf080797ba7.md|Issue fin-e07debf080797ba7]]
#### Observations
- [[occurrences/occ-76cae58969e7fe60.md|allowInsecureScheme]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-11f1f8346939f202.md|Issue fin-11f1f8346939f202]]
#### Observations
- [[occurrences/occ-200217f445c7cc74.md|allowNullOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5c1d3b637ab73f89.md|Issue fin-5c1d3b637ab73f89]]
#### Observations
- [[occurrences/occ-b9f67bf761fd7b09.md|allowNullOrigin]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-045bc8f099cab145.md|Issue fin-045bc8f099cab145]]
#### Observations
- [[occurrences/occ-f443f49b1cb5cf13.md|allowOriginEndsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e1d5f0f1073be3f6.md|Issue fin-e1d5f0f1073be3f6]]
#### Observations
- [[occurrences/occ-2aaa069cce3cfaa5.md|allowOriginEndsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginProtocolDowngrade  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-02363dfb74d2c76a.md|Issue fin-02363dfb74d2c76a]]
#### Observations
- [[occurrences/occ-72ee8767d7fcd603.md|allowOriginProtocolDowngrade]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginRegexDot  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-54d107e578ef937f.md|Issue fin-54d107e578ef937f]]
#### Observations
- [[occurrences/occ-d81cb252e4011e8c.md|allowOriginRegexDot]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5298a8262937d86c.md|Issue fin-5298a8262937d86c]]
#### Observations
- [[occurrences/occ-29e021fb3adbc508.md|allowOriginStartsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6665f7c66f18fb55.md|Issue fin-6665f7c66f18fb55]]
#### Observations
- [[occurrences/occ-e0cf9684342533cb.md|allowOriginStartsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-299a0ed9e543d95b.md|Issue fin-299a0ed9e543d95b]]
#### Observations
- [[occurrences/occ-83509e19f2a3289c.md|dynamicAllowOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5b3b24ceaea1d4aa.md|Issue fin-5b3b24ceaea1d4aa]]
#### Observations
- [[occurrences/occ-6718ab8f33f3b9d2.md|dynamicAllowOrigin]]

### GET https://public-firing-range.appspot.com/cors/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b8f908cbb1a52afc.md|Issue fin-b8f908cbb1a52afc]]
#### Observations
- [[occurrences/occ-a357fece1c15ecf6.md|cors/index.html]]

### GET https://public-firing-range.appspot.com/dom  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e5fea6c654bef04a.md|Issue fin-e5fea6c654bef04a]]
#### Observations
- [[occurrences/occ-12dfa583a10ea409.md|dom]]

### GET https://public-firing-range.appspot.com/dom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b23e28d08b9c4e80.md|Issue fin-b23e28d08b9c4e80]]
#### Observations
- [[occurrences/occ-f7eb2ff52613ace8.md|dom]]

### GET https://public-firing-range.appspot.com/dom/dompropagation  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2955d0213dd8b044.md|Issue fin-2955d0213dd8b044]]
#### Observations
- [[occurrences/occ-17bae023aca9c64f.md|dompropagation]]

### GET https://public-firing-range.appspot.com/dom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9862c7e06f404672.md|Issue fin-9862c7e06f404672]]
#### Observations
- [[occurrences/occ-c867970b18952304.md|dom/index.html]]

### GET https://public-firing-range.appspot.com/dom/javascripturi.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-55991d6fcd00a8ae.md|Issue fin-55991d6fcd00a8ae]]
#### Observations
- [[occurrences/occ-b12b8da5a173b982.md|javascripturi.html]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1d6b7cd3216f09f0.md|Issue fin-1d6b7cd3216f09f0]]
#### Observations
- [[occurrences/occ-cab6f49f9a2d9561.md|complexMessageDocumentWriteEval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bf49a436456af6b5.md|Issue fin-bf49a436456af6b5]]
#### Observations
- [[occurrences/occ-ba0e21ddbcc0de20.md|documentWrite]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6e4d7039f37d3617.md|Issue fin-6e4d7039f37d3617]]
#### Observations
- [[occurrences/occ-3f17a4378e214296.md|eval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ffb772fee8d8ecc5.md|Issue fin-ffb772fee8d8ecc5]]
#### Observations
- [[occurrences/occ-2cc995f21bad38e5.md|improperOriginValid…tialStringComparison]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-be68cc358d88a3e2.md|Issue fin-be68cc358d88a3e2]]
#### Observations
- [[occurrences/occ-8de3bcce7d8159df.md|improperOriginValidationWithRegExp]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-18347493db7114c4.md|Issue fin-18347493db7114c4]]
#### Observations
- [[occurrences/occ-cecc052fd29a39c8.md|innerHtml]]

### GET https://public-firing-range.appspot.com/escape  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f720b96dca8879bd.md|Issue fin-f720b96dca8879bd]]
#### Observations
- [[occurrences/occ-fc2d53388da934da.md|escape]]

### GET https://public-firing-range.appspot.com/escape/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3fc5f14464028482.md|Issue fin-3fc5f14464028482]]
#### Observations
- [[occurrences/occ-7ea1d3abf22e9216.md|escape]]

### GET https://public-firing-range.appspot.com/escape/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0e7461b92da13f72.md|Issue fin-0e7461b92da13f72]]
#### Observations
- [[occurrences/occ-e442c7843494d41a.md|escape/index.html]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee226f42eefb43f0.md|Issue fin-ee226f42eefb43f0]]
#### Observations
- [[occurrences/occ-6465e35dc0b55f28.md|encodeURIComponent]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-59469d9c745ef2e4.md|Issue fin-59469d9c745ef2e4]]
#### Observations
- [[occurrences/occ-9d00784e7a5419b7.md|escape]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-89350ec12ec980fa.md|Issue fin-89350ec12ec980fa]]
#### Observations
- [[occurrences/occ-fa4d22bac5ed3a4b.md|html_escape]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-995434ba78972eed.md|Issue fin-995434ba78972eed]]
#### Observations
- [[occurrences/occ-7abaf9dce08d43d8.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6494b2d0b161e7ea.md|Issue fin-6494b2d0b161e7ea]]
#### Observations
- [[occurrences/occ-cdacccb6c647ab36.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-032d6e495bf1378f.md|Issue fin-032d6e495bf1378f]]
#### Observations
- [[occurrences/occ-f55cacb970862689.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a1d7c3c4cf26bb31.md|Issue fin-a1d7c3c4cf26bb31]]
#### Observations
- [[occurrences/occ-33a6e58ab7f8fef3.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-875389ee2544b733.md|Issue fin-875389ee2544b733]]
#### Observations
- [[occurrences/occ-8e4bfe7a77d40d90.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cebf6aee3f172c18.md|Issue fin-cebf6aee3f172c18]]
#### Observations
- [[occurrences/occ-4ecd03126f4ffe53.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a5bc3d7f4e2f55a4.md|Issue fin-a5bc3d7f4e2f55a4]]
#### Observations
- [[occurrences/occ-739b3abee646f5e9.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2c4d91d9b461683a.md|Issue fin-2c4d91d9b461683a]]
#### Observations
- [[occurrences/occ-299935414a7098ab.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f44933f71891f49.md|Issue fin-7f44933f71891f49]]
#### Observations
- [[occurrences/occ-ba6869007358d3d8.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c2d84dca0f5bb59.md|Issue fin-0c2d84dca0f5bb59]]
#### Observations
- [[occurrences/occ-edfc63f2e6d6d505.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8500ad6b43f21d3b.md|Issue fin-8500ad6b43f21d3b]]
#### Observations
- [[occurrences/occ-95b75d91534edb5c.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2ed8cefd2346851f.md|Issue fin-2ed8cefd2346851f]]
#### Observations
- [[occurrences/occ-97e11334a2e65642.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d2438dbd8946aa2e.md|Issue fin-d2438dbd8946aa2e]]
#### Observations
- [[occurrences/occ-6c5bc40c2b27e3d2.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d922f11f095df6b7.md|Issue fin-d922f11f095df6b7]]
#### Observations
- [[occurrences/occ-c5db6565f3e1daab.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-43ae869aa5968836.md|Issue fin-43ae869aa5968836]]
#### Observations
- [[occurrences/occ-f87c193d787765f9.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9eaa1f4e3084cdbd.md|Issue fin-9eaa1f4e3084cdbd]]
#### Observations
- [[occurrences/occ-ae874e62c907fb68.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8337544361c039c9.md|Issue fin-8337544361c039c9]]
#### Observations
- [[occurrences/occ-77785e705f6c8b11.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-87145c1a393a925d.md|Issue fin-87145c1a393a925d]]
#### Observations
- [[occurrences/occ-172934348e53621b.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e58d1da8c0f44a23.md|Issue fin-e58d1da8c0f44a23]]
#### Observations
- [[occurrences/occ-111daf8ef843c25b.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ece15b810fa13980.md|Issue fin-ece15b810fa13980]]
#### Observations
- [[occurrences/occ-0a29477f98569e9a.md|textarea]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-86dd5e1a42aa3389.md|Issue fin-86dd5e1a42aa3389]]
#### Observations
- [[occurrences/occ-b0079f1fbd541c97.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-adc3c2f5ff193a07.md|Issue fin-adc3c2f5ff193a07]]
#### Observations
- [[occurrences/occ-513633888ab234b3.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e0378d780073349b.md|Issue fin-e0378d780073349b]]
#### Observations
- [[occurrences/occ-fdea2665be3f1173.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7ac9d4e6e9d112cb.md|Issue fin-7ac9d4e6e9d112cb]]
#### Observations
- [[occurrences/occ-f56fd08ec3fd261c.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-df559a8638267afc.md|Issue fin-df559a8638267afc]]
#### Observations
- [[occurrences/occ-6e4ff31653ae7efe.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee1a466d9c0a1613.md|Issue fin-ee1a466d9c0a1613]]
#### Observations
- [[occurrences/occ-90d0ad724376af0a.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bd05faca5f9d8cbd.md|Issue fin-bd05faca5f9d8cbd]]
#### Observations
- [[occurrences/occ-b256fab527cf1857.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7fb0d0310b1d0230.md|Issue fin-7fb0d0310b1d0230]]
#### Observations
- [[occurrences/occ-23f5a8d5bfcf47a1.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-531277b536da0ec4.md|Issue fin-531277b536da0ec4]]
#### Observations
- [[occurrences/occ-ce1a7fc4135aebf2.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-021ade69710d256c.md|Issue fin-021ade69710d256c]]
#### Observations
- [[occurrences/occ-8e39ecc4a5700fda.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_value?q=a&escape=HTML_ESCAPE  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4f1fe64519984b75.md|Issue fin-4f1fe64519984b75]]
#### Observations
- [[occurrences/occ-76a6b6220f78bdf3.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6ac9f846d4897174.md|Issue fin-6ac9f846d4897174]]
#### Observations
- [[occurrences/occ-73fb45b020e3be02.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-72f56cb6a4191f20.md|Issue fin-72f56cb6a4191f20]]
#### Observations
- [[occurrences/occ-da31ea693ee0e5aa.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bb386f134f66a0ab.md|Issue fin-bb386f134f66a0ab]]
#### Observations
- [[occurrences/occ-8d581c9ab864198d.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2565f34e60bda444.md|Issue fin-2565f34e60bda444]]
#### Observations
- [[occurrences/occ-da8a9db252d1dc9e.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a8348822ad9953a5.md|Issue fin-a8348822ad9953a5]]
#### Observations
- [[occurrences/occ-9213a21bd5b3c6ff.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2ed9c1a41113439e.md|Issue fin-2ed9c1a41113439e]]
#### Observations
- [[occurrences/occ-d10a1481fdd21b62.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-295b638fa4c5c9dd.md|Issue fin-295b638fa4c5c9dd]]
#### Observations
- [[occurrences/occ-130d947277c3a081.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b4e493e253b811e1.md|Issue fin-b4e493e253b811e1]]
#### Observations
- [[occurrences/occ-6513192e96f7077b.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-623f29633bfe30f3.md|Issue fin-623f29633bfe30f3]]
#### Observations
- [[occurrences/occ-0436d0d842cd038e.md|textarea]]

### GET https://public-firing-range.appspot.com/flashinjection  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-18c10fc760e7780b.md|Issue fin-18c10fc760e7780b]]
#### Observations
- [[occurrences/occ-832444754b527949.md|flashinjection]]

### GET https://public-firing-range.appspot.com/flashinjection/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ca949ba3ec2dea6e.md|Issue fin-ca949ba3ec2dea6e]]
#### Observations
- [[occurrences/occ-859664cfacda9393.md|flashinjection]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackIsEchoedBack?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-627a65a3d904c46c.md|Issue fin-627a65a3d904c46c]]
#### Observations
- [[occurrences/occ-1f77d37e81ca09e4.md|callbackIsEchoedBack]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackParameterDoesNothing?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-026e5e6fa90dd9db.md|Issue fin-026e5e6fa90dd9db]]
#### Observations
- [[occurrences/occ-05de9183a71d16e4.md|callbackParameterDoesNothing]]

### GET https://public-firing-range.appspot.com/flashinjection/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-acdcbc199dcb9fc2.md|Issue fin-acdcbc199dcb9fc2]]
#### Observations
- [[occurrences/occ-0525e35b83a6f9f3.md|flashinjection/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6e8c5ffd0071a610.md|Issue fin-6e8c5ffd0071a610]]
#### Observations
- [[occurrences/occ-1cc8cb813e312426.md|insecurethirdpartyscripts]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-41acb7abc8a3fdda.md|Issue fin-41acb7abc8a3fdda]]
#### Observations
- [[occurrences/occ-b55f026d13908ac3.md|insecurethirdpartyscripts]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0374b1d8c8a11081.md|Issue fin-0374b1d8c8a11081]]
#### Observations
- [[occurrences/occ-64f54aee9df0b35c.md|insecurethirdpartyscripts/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-391c2a282c66bfe2.md|Issue fin-391c2a282c66bfe2]]
#### Observations
- [[occurrences/occ-bec04c62edf357e6.md|third_party_scripts…ource_integrity.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-60e3fd11a982da0d.md|Issue fin-60e3fd11a982da0d]]
#### Observations
- [[occurrences/occ-0fd6922b0dc42153.md|third_party_scripts…namically_added.html]]

### GET https://public-firing-range.appspot.com/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f3210218623bf9cf.md|Issue fin-f3210218623bf9cf]]
#### Observations
- [[occurrences/occ-938eceaee8ec667f.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b2138a1098eaee65.md|Issue fin-b2138a1098eaee65]]
#### Observations
- [[occurrences/occ-0b50f286fd8ef2ee.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cea6ebe53dda7bb8.md|Issue fin-cea6ebe53dda7bb8]]
#### Observations
- [[occurrences/occ-6e875277ab5f4e4c.md|leakedcookie/index.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-052d051c1a1329e4.md|Issue fin-052d051c1a1329e4]]
#### Observations
- [[occurrences/occ-60b023f6f8eca467.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eb05c105243d54e6.md|Issue fin-eb05c105243d54e6]]
#### Observations
- [[occurrences/occ-8a238713a11ea58c.md|leakedinresource]]

### GET https://public-firing-range.appspot.com/mixedcontent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-53ddcb5c176ab954.md|Issue fin-53ddcb5c176ab954]]
#### Observations
- [[occurrences/occ-93ba30dd588e7c56.md|mixedcontent]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-712ea818b130aae3.md|Issue fin-712ea818b130aae3]]
#### Observations
- [[occurrences/occ-3ffcccd58b2c20c2.md|mixedcontent]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-da9bd31ffbf42db9.md|Issue fin-da9bd31ffbf42db9]]
#### Observations
- [[occurrences/occ-2c84b970b7935e3f.md|mixedcontent/index.html]]

### GET https://public-firing-range.appspot.com/redirect  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-64a3bed1ef964ce1.md|Issue fin-64a3bed1ef964ce1]]
#### Observations
- [[occurrences/occ-01e112a7f4d97d26.md|redirect]]

### GET https://public-firing-range.appspot.com/redirect/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9f6213f05b93f747.md|Issue fin-9f6213f05b93f747]]
#### Observations
- [[occurrences/occ-7e0612d58d8bbdfc.md|redirect]]

### GET https://public-firing-range.appspot.com/redirect/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-18d5048409f2c937.md|Issue fin-18d5048409f2c937]]
#### Observations
- [[occurrences/occ-9ce4c05d2e8c138b.md|redirect/index.html]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-76f995117db4c72f.md|Issue fin-76f995117db4c72f]]
#### Observations
- [[occurrences/occ-f6d8975391c606f1.md|meta]]

### GET https://public-firing-range.appspot.com/reflected  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1cb4da55f005548e.md|Issue fin-1cb4da55f005548e]]
#### Observations
- [[occurrences/occ-2f872c91cb59a9f4.md|reflected]]

### GET https://public-firing-range.appspot.com/reflected/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4bdb3a5cd246595d.md|Issue fin-4bdb3a5cd246595d]]
#### Observations
- [[occurrences/occ-210c63cd42a53004.md|reflected]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-27823653b8398923.md|Issue fin-27823653b8398923]]
#### Observations
- [[occurrences/occ-78c28ec030c92999.md|json]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/plaintext?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a480b8d59d870900.md|Issue fin-a480b8d59d870900]]
#### Observations
- [[occurrences/occ-4399b6a59a6ac0a3.md|plaintext]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a202c9f3e5f83143.md|Issue fin-a202c9f3e5f83143]]
#### Observations
- [[occurrences/occ-bf8a16516a4e0221.md|DOUBLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d4f2ed17616d4df3.md|Issue fin-d4f2ed17616d4df3]]
#### Observations
- [[occurrences/occ-fa323a61db08fd07.md|SINGLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-161f3323ef1a8379.md|Issue fin-161f3323ef1a8379]]
#### Observations
- [[occurrences/occ-8ec696322bf1ea15.md|UNQUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7ad018c445fa735a.md|Issue fin-7ad018c445fa735a]]
#### Observations
- [[occurrences/occ-5a91bb8d8a3e6dc3.md|DoubleQuoteSinglequote]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9a40e4e02d674bfc.md|Issue fin-9a40e4e02d674bfc]]
#### Observations
- [[occurrences/occ-e8a52b1b4468c6a7.md|SpaceDoubleQuoteSlashEquals]]

### GET https://public-firing-range.appspot.com/reflected/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b5d4d90dfb1f0d9.md|Issue fin-8b5d4d90dfb1f0d9]]
#### Observations
- [[occurrences/occ-84fdc7fbbe8cab39.md|reflected/index.html]]

### GET https://public-firing-range.appspot.com/reflected/jsoncallback  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b305094e816f8feb.md|Issue fin-b305094e816f8feb]]
#### Observations
- [[occurrences/occ-1ccacfd60e754cf3.md|jsoncallback]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-40d5cd74f2d74580.md|Issue fin-40d5cd74f2d74580]]
#### Observations
- [[occurrences/occ-174d35ad86af8f55.md|attribute_name]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-57104a95dac22956.md|Issue fin-57104a95dac22956]]
#### Observations
- [[occurrences/occ-867e36b7b31092c2.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9f10a9353eac0cb9.md|Issue fin-9f10a9353eac0cb9]]
#### Observations
- [[occurrences/occ-831f936ab8f26bc9.md|attribute_script]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4ac557458cda9811.md|Issue fin-4ac557458cda9811]]
#### Observations
- [[occurrences/occ-1b6230abf18d68bb.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d9df94f397f4ae33.md|Issue fin-d9df94f397f4ae33]]
#### Observations
- [[occurrences/occ-68c689811b63ee0d.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4003e270ce56ab23.md|Issue fin-4003e270ce56ab23]]
#### Observations
- [[occurrences/occ-f891accf1517e3a1.md|body]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1ffb5f91e9a8d936.md|Issue fin-1ffb5f91e9a8d936]]
#### Observations
- [[occurrences/occ-b5f4e29068362251.md|body]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-60bcd5c8c809c9d5.md|Issue fin-60bcd5c8c809c9d5]]
#### Observations
- [[occurrences/occ-b4694435be377783.md|body_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fb17880a9a14989c.md|Issue fin-fb17880a9a14989c]]
#### Observations
- [[occurrences/occ-9ffac7f742bf2cbb.md|css_style]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-42a79622257485c8.md|Issue fin-42a79622257485c8]]
#### Observations
- [[occurrences/occ-9d2591fc56f8ed51.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-92c87fb2dc0b427d.md|Issue fin-92c87fb2dc0b427d]]
#### Observations
- [[occurrences/occ-37e1ef7ada1594b7.md|css_style_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/form  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7660ebab8d931af8.md|Issue fin-7660ebab8d931af8]]
#### Observations
- [[occurrences/occ-a06d38a4a679cc9b.md|form]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d3f436b284db7243.md|Issue fin-d3f436b284db7243]]
#### Observations
- [[occurrences/occ-5f8361ccbf7e0619.md|head]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-36b27b9fb3891a29.md|Issue fin-36b27b9fb3891a29]]
#### Observations
- [[occurrences/occ-ee0ab56bc61eaadf.md|iframe_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8cd374c6d672079a.md|Issue fin-8cd374c6d672079a]]
#### Observations
- [[occurrences/occ-2748b0a32246b31f.md|iframe_srcdoc]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-23fa77de33c51b5d.md|Issue fin-23fa77de33c51b5d]]
#### Observations
- [[occurrences/occ-6410663034590df2.md|js_assignment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db91fd34094ac4a9.md|Issue fin-db91fd34094ac4a9]]
#### Observations
- [[occurrences/occ-701f982a59eacb7f.md|js_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f876f53f35a24bf7.md|Issue fin-f876f53f35a24bf7]]
#### Observations
- [[occurrences/occ-49ff69ec85861e3e.md|js_eval]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c2397a1aacb8ddb.md|Issue fin-0c2397a1aacb8ddb]]
#### Observations
- [[occurrences/occ-f534d58a716785ea.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a5711d3ccda62088.md|Issue fin-a5711d3ccda62088]]
#### Observations
- [[occurrences/occ-8bb3909ff77973fa.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-470b04e29e104728.md|Issue fin-470b04e29e104728]]
#### Observations
- [[occurrences/occ-1b57efb0cc222450.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5f0a045c4ceb7650.md|Issue fin-5f0a045c4ceb7650]]
#### Observations
- [[occurrences/occ-2328add9f58f26c9.md|json]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-15f7f04693c62bb2.md|Issue fin-15f7f04693c62bb2]]
#### Observations
- [[occurrences/occ-c13dd6663b5b9ed1.md|noscript]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0a5c292935fc2b7e.md|Issue fin-0a5c292935fc2b7e]]
#### Observations
- [[occurrences/occ-9edc7f4e84081035.md|style_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6f346c894ff2147f.md|Issue fin-6f346c894ff2147f]]
#### Observations
- [[occurrences/occ-9418f796d0c22002.md|tagname]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f9be86d6b9bf9305.md|Issue fin-f9be86d6b9bf9305]]
#### Observations
- [[occurrences/occ-9be9e97e57ef9c45.md|textarea]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e3797d3df38851c2.md|Issue fin-e3797d3df38851c2]]
#### Observations
- [[occurrences/occ-069a0ffc52ae7eed.md|textarea_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c1fe80038e1beeaf.md|Issue fin-c1fe80038e1beeaf]]
#### Observations
- [[occurrences/occ-5fd7a8ee1fc7d32f.md|title]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f7cd4094a90bc180.md|Issue fin-f7cd4094a90bc180]]
#### Observations
- [[occurrences/occ-63ade5c091a459eb.md|css_import]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-68f7935779f4bb37.md|Issue fin-68f7935779f4bb37]]
#### Observations
- [[occurrences/occ-4282b4562501acaf.md|href]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c9fe5c1102dd141d.md|Issue fin-c9fe5c1102dd141d]]
#### Observations
- [[occurrences/occ-3ac746e52a55bb17.md|object_data]]

### GET https://public-firing-range.appspot.com/reflected/url/object_param?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1a6f4fb66945d66b.md|Issue fin-1a6f4fb66945d66b]]
#### Observations
- [[occurrences/occ-d8d327d63e3d4f3d.md|object_param]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-92549ec71b2ae077.md|Issue fin-92549ec71b2ae077]]
#### Observations
- [[occurrences/occ-d959ad4065c6cbe4.md|script_src]]

### GET https://public-firing-range.appspot.com/remoteinclude  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-93d0785cf6ef25db.md|Issue fin-93d0785cf6ef25db]]
#### Observations
- [[occurrences/occ-b590bd4c8807bcd0.md|remoteinclude]]

### GET https://public-firing-range.appspot.com/remoteinclude/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee7451c12874af98.md|Issue fin-ee7451c12874af98]]
#### Observations
- [[occurrences/occ-bce1be0f82106ba8.md|remoteinclude]]

### GET https://public-firing-range.appspot.com/remoteinclude/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8390233167c4b589.md|Issue fin-8390233167c4b589]]
#### Observations
- [[occurrences/occ-8630848e494f0d46.md|remoteinclude/index.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-971ce4bffd69b750.md|Issue fin-971ce4bffd69b750]]
#### Observations
- [[occurrences/occ-e5e9c58a40dc5fbc.md|object_hash.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a4697ac3ffeb5674.md|Issue fin-a4697ac3ffeb5674]]
#### Observations
- [[occurrences/occ-287765c1ce797261.md|application_x-shockwave-flash]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e5867666f2abd319.md|Issue fin-e5867666f2abd319]]
#### Observations
- [[occurrences/occ-085340872eb1a29d.md|object_raw]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5732188342d29ee2.md|Issue fin-5732188342d29ee2]]
#### Observations
- [[occurrences/occ-94fd1a5abc899a7f.md|script]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-68a1234de95c5ed7.md|Issue fin-68a1234de95c5ed7]]
#### Observations
- [[occurrences/occ-614446958ead1c5a.md|script_hash.html]]

### GET https://public-firing-range.appspot.com/reverseclickjacking  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e2c72d7abdf68cd.md|Issue fin-7e2c72d7abdf68cd]]
#### Observations
- [[occurrences/occ-70fe6dd1f0b45111.md|reverseclickjacking]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-260d5e192e3bb815.md|Issue fin-260d5e192e3bb815]]
#### Observations
- [[occurrences/occ-ce0ce2b51c0fa1ec.md|reverseclickjacking]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-be1b585523c695f4.md|Issue fin-be1b585523c695f4]]
#### Observations
- [[occurrences/occ-68d9f3e4a4cb00e3.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f07bb8a5946d5d3b.md|Issue fin-f07bb8a5946d5d3b]]
#### Observations
- [[occurrences/occ-a8055691906788fc.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-24511c6548978d43.md|Issue fin-24511c6548978d43]]
#### Observations
- [[occurrences/occ-f1f2ec450418edc7.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b60c11235a4356f9.md|Issue fin-b60c11235a4356f9]]
#### Observations
- [[occurrences/occ-3330f0eabd9b6408.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b82738f98b48c068.md|Issue fin-b82738f98b48c068]]
#### Observations
- [[occurrences/occ-bfd21928e004d19a.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-933c9fe30c15bd7d.md|Issue fin-933c9fe30c15bd7d]]
#### Observations
- [[occurrences/occ-afeff98e1655372c.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-df616763efbc909c.md|Issue fin-df616763efbc909c]]
#### Observations
- [[occurrences/occ-e5e4b362464af591.md|stricttransportsecurity]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0aaf2738b9b99a96.md|Issue fin-0aaf2738b9b99a96]]
#### Observations
- [[occurrences/occ-3f3b9425e01a98c8.md|stricttransportsecurity]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_includesubdomains_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8ccc36d857686974.md|Issue fin-8ccc36d857686974]]
#### Observations
- [[occurrences/occ-f1dfd7e151b72826.md|hsts_includesubdomains_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c7b570d88f82b2d.md|Issue fin-0c7b570d88f82b2d]]
#### Observations
- [[occurrences/occ-c75b295861858246.md|hsts_max_age_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_too_low  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-679bb78af592b186.md|Issue fin-679bb78af592b186]]
#### Observations
- [[occurrences/occ-fac5d34ee25ef538.md|hsts_max_age_too_low]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cc318f75b90d56bb.md|Issue fin-cc318f75b90d56bb]]
#### Observations
- [[occurrences/occ-3bc1faee4ed1e67b.md|hsts_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_preload_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8986f4d6e4875635.md|Issue fin-8986f4d6e4875635]]
#### Observations
- [[occurrences/occ-6cb9e679ff1e613b.md|hsts_preload_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-854a49b09351173c.md|Issue fin-854a49b09351173c]]
#### Observations
- [[occurrences/occ-a8cd5b9415177c30.md|stricttransportsecurity/index.html]]

### GET https://public-firing-range.appspot.com/tags  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e45028d6c9deccec.md|Issue fin-e45028d6c9deccec]]
#### Observations
- [[occurrences/occ-f1c96be61459f4e6.md|tags]]

### GET https://public-firing-range.appspot.com/tags/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ca6a89343d6e20d7.md|Issue fin-ca6a89343d6e20d7]]
#### Observations
- [[occurrences/occ-f35ac0cc0d340544.md|tags]]

### GET https://public-firing-range.appspot.com/tags/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6b4eb8449403cffd.md|Issue fin-6b4eb8449403cffd]]
#### Observations
- [[occurrences/occ-f4a736c04e542326.md|tags/index.html]]

### GET https://public-firing-range.appspot.com/tags/multiline?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9904b9366608c144.md|Issue fin-9904b9366608c144]]
#### Observations
- [[occurrences/occ-f4b39bdb238edfca.md|multiline]]

### GET https://public-firing-range.appspot.com/urldom  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8d0b73843bad4861.md|Issue fin-8d0b73843bad4861]]
#### Observations
- [[occurrences/occ-77f558378377e570.md|urldom]]

### GET https://public-firing-range.appspot.com/urldom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b35ae7c09c918f08.md|Issue fin-b35ae7c09c918f08]]
#### Observations
- [[occurrences/occ-8bdefd2c4dd36820.md|urldom]]

### GET https://public-firing-range.appspot.com/urldom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6afda3e634fbf716.md|Issue fin-6afda3e634fbf716]]
#### Observations
- [[occurrences/occ-dd59aebb378842a1.md|urldom/index.html]]

### GET https://public-firing-range.appspot.com/urldom/jsonp?callback=foobar  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ca4a075335af3c19.md|Issue fin-ca4a075335af3c19]]
#### Observations
- [[occurrences/occ-2c4b65596443689e.md|jsonp]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_domain  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4d04d48373437e75.md|Issue fin-4d04d48373437e75]]
#### Observations
- [[occurrences/occ-7514d6afddf69a0a.md|script.src.partial_domain]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_query  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-658cd2a395a9b0ce.md|Issue fin-658cd2a395a9b0ce]]
#### Observations
- [[occurrences/occ-cb5d2066dd0c9d0a.md|script.src.partial_query]]

### GET https://public-firing-range.appspot.com/urldom/location/search/area.href?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bc2c2e04a8d81754.md|Issue fin-bc2c2e04a8d81754]]
#### Observations
- [[occurrences/occ-b4dafec7e9cef6d8.md|area.href]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-62cd892df4e7b608.md|Issue fin-62cd892df4e7b608]]
#### Observations
- [[occurrences/occ-04180b9c8e456699.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2c5d1133092a4734.md|Issue fin-2c5d1133092a4734]]
#### Observations
- [[occurrences/occ-e8afd7749126f6dc.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/frame.src?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8ca78c5ea8f0ba2d.md|Issue fin-8ca78c5ea8f0ba2d]]
#### Observations
- [[occurrences/occ-864a169abbf770e2.md|frame.src]]

### GET https://public-firing-range.appspot.com/urldom/location/search/location.assign?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aa67155bd415b66c.md|Issue fin-aa67155bd415b66c]]
#### Observations
- [[occurrences/occ-e1b451d92f18f9f0.md|location.assign]]

### GET https://public-firing-range.appspot.com/urldom/location/search/svg.a?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e9985d577cfa4212.md|Issue fin-e9985d577cfa4212]]
#### Observations
- [[occurrences/occ-2a1eb2ac81324cd2.md|svg.a]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-317f63e59435522d.md|Issue fin-317f63e59435522d]]
#### Observations
- [[occurrences/occ-8eb6b4e337c39426.md|vulnerablelibraries]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc3e14ef5962c896.md|Issue fin-fc3e14ef5962c896]]
#### Observations
- [[occurrences/occ-425d9b0b3e431269.md|vulnerablelibraries]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef145c1290379cf6.md|Issue fin-ef145c1290379cf6]]
#### Observations
- [[occurrences/occ-aadbf47e45e2eea8.md|vulnerablelibraries/index.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a75485ad32c30a40.md|Issue fin-a75485ad32c30a40]]
#### Observations
- [[occurrences/occ-fa5a280db6d65dd5.md|jquery.html]]

