---
aliases:
  - "SCC-0049"
cweId: "524"
cweUri: "https://cwe.mitre.org/data/definitions/524.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10049"
name: "Storable and Cacheable Content"
occurrenceCount: "251"
pluginId: "10049"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "251"
wascId: "13"
---

# Storable and Cacheable Content (Plugin 10049)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/CacheableScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/CacheableScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10049/

### How it detects

Passive; checks headers: Pragma, Cache-Control, Authorization; sets evidence

Signals:
- header:Pragma
- header:Cache-Control
- header:Authorization

## Remediation

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### References
- https://datatracker.ietf.org/doc/html/rfc7234
- https://datatracker.ietf.org/doc/html/rfc7231
- https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fe8d6b9ba64e69af.md|Issue fin-fe8d6b9ba64e69af]]
#### Observations
- [[occurrences/occ-a6d8560615047989.md|public-firing-range.appspot.com/]]

### GET https://public-firing-range.appspot.com/address/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5e635f3df25d00d3.md|Issue fin-5e635f3df25d00d3]]
#### Observations
- [[occurrences/occ-28c52dfd2e882232.md|address]]

### GET https://public-firing-range.appspot.com/address/URL/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-93605951a489fb98.md|Issue fin-93605951a489fb98]]
#### Observations
- [[occurrences/occ-3743dd8b83835551.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/URLUnencoded/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c88404e844c9911b.md|Issue fin-c88404e844c9911b]]
#### Observations
- [[occurrences/occ-a57a3c8556a66700.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/baseURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fca5e7cb96513bda.md|Issue fin-fca5e7cb96513bda]]
#### Observations
- [[occurrences/occ-32b46f2cc4c15f90.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/documentURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b08f0b8dbd5b3606.md|Issue fin-b08f0b8dbd5b3606]]
#### Observations
- [[occurrences/occ-ef2320779d2e1511.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2cd643f13070251f.md|Issue fin-2cd643f13070251f]]
#### Observations
- [[occurrences/occ-4bfcec1a1ab17dbe.md|address/index.html]]

### GET https://public-firing-range.appspot.com/address/location.hash/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e89c8fd7b862393e.md|Issue fin-e89c8fd7b862393e]]
#### Observations
- [[occurrences/occ-3863b1bd93ef5a51.md|assign]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6c605b9fa75858a9.md|Issue fin-6c605b9fa75858a9]]
#### Observations
- [[occurrences/occ-633ac65f51cf2785.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-571d23b9aa5403c0.md|Issue fin-571d23b9aa5403c0]]
#### Observations
- [[occurrences/occ-b5395c9156d7ef50.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1569b347b9a16a3d.md|Issue fin-1569b347b9a16a3d]]
#### Observations
- [[occurrences/occ-00e9a769c50bc1a3.md|eval]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2b8560dd4178be5b.md|Issue fin-2b8560dd4178be5b]]
#### Observations
- [[occurrences/occ-f3aca8bc0ce72717.md|formaction]]

### GET https://public-firing-range.appspot.com/address/location.hash/function  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a9db9be4241c9954.md|Issue fin-a9db9be4241c9954]]
#### Observations
- [[occurrences/occ-bcefb06005139caf.md|function]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bd2acbf37f463cc3.md|Issue fin-bd2acbf37f463cc3]]
#### Observations
- [[occurrences/occ-bae9f9fdd68e48a2.md|inlineevent]]

### GET https://public-firing-range.appspot.com/address/location.hash/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6a097c57b88bd492.md|Issue fin-6a097c57b88bd492]]
#### Observations
- [[occurrences/occ-2b86cca0a054f41a.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location.hash/jshref  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-676a129efbbd60e5.md|Issue fin-676a129efbbd60e5]]
#### Observations
- [[occurrences/occ-b754cb16bb8d89d0.md|jshref]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickAddEventListener  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6db96b9deda586b6.md|Issue fin-6db96b9deda586b6]]
#### Observations
- [[occurrences/occ-e4dc91a62308b105.md|onclickAddEventListener]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickSetAttribute  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-707b1df899cebd7f.md|Issue fin-707b1df899cebd7f]]
#### Observations
- [[occurrences/occ-26f9e0bcd77e9e6f.md|onclickSetAttribute]]

### GET https://public-firing-range.appspot.com/address/location.hash/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f0ce766c70a65a8.md|Issue fin-7f0ce766c70a65a8]]
#### Observations
- [[occurrences/occ-6aeb31afc4601ac6.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6c3e81d9d09ecd7a.md|Issue fin-6c3e81d9d09ecd7a]]
#### Observations
- [[occurrences/occ-e05dd3abf61c1c99.md|replace]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc864607d0eec74a.md|Issue fin-fc864607d0eec74a]]
#### Observations
- [[occurrences/occ-c77fbcbbf447009c.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/location/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-35f0462ee85922ab.md|Issue fin-35f0462ee85922ab]]
#### Observations
- [[occurrences/occ-3b19b7d7459f3b65.md|assign]]

### GET https://public-firing-range.appspot.com/address/location/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6980b7ca6cd3e788.md|Issue fin-6980b7ca6cd3e788]]
#### Observations
- [[occurrences/occ-e072666b69224a19.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/location/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f34af204854d80fb.md|Issue fin-f34af204854d80fb]]
#### Observations
- [[occurrences/occ-d384621b12203e1f.md|documentwriteln]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-30f7f14fdf367add.md|Issue fin-30f7f14fdf367add]]
#### Observations
- [[occurrences/occ-e1ce0b0d2039f3f3.md|eval]]

### GET https://public-firing-range.appspot.com/address/location/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9e129fb546729f5d.md|Issue fin-9e129fb546729f5d]]
#### Observations
- [[occurrences/occ-5fbc48e559e54012.md|innerHtml]]

### GET https://public-firing-range.appspot.com/address/location/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-98e40f2f2a60f594.md|Issue fin-98e40f2f2a60f594]]
#### Observations
- [[occurrences/occ-c4cb554f12bdba2d.md|rangeCreateContextualFragment]]

### GET https://public-firing-range.appspot.com/address/location/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b5c5b6e9d88f1820.md|Issue fin-b5c5b6e9d88f1820]]
#### Observations
- [[occurrences/occ-14bd23c000766a1a.md|replace]]

### GET https://public-firing-range.appspot.com/address/location/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b0ebc7255327f90.md|Issue fin-7b0ebc7255327f90]]
#### Observations
- [[occurrences/occ-43bae5a1a794bce8.md|setTimeout]]

### GET https://public-firing-range.appspot.com/address/locationhref/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cb30d22090c447d8.md|Issue fin-cb30d22090c447d8]]
#### Observations
- [[occurrences/occ-e08bbc1059e3bfb6.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationpathname/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aa198f711ae211f8.md|Issue fin-aa198f711ae211f8]]
#### Observations
- [[occurrences/occ-3c435e7f77f8ce6f.md|documentwrite]]

### GET https://public-firing-range.appspot.com/address/locationsearch/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a824e4d3dfd571ae.md|Issue fin-a824e4d3dfd571ae]]
#### Observations
- [[occurrences/occ-4dffa4613d818ed1.md|documentwrite]]

### GET https://public-firing-range.appspot.com/angular/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-28d30d2c53516284.md|Issue fin-28d30d2c53516284]]
#### Observations
- [[occurrences/occ-038bee8680faa991.md|angular]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f47688527eef1fb5.md|Issue fin-f47688527eef1fb5]]
#### Observations
- [[occurrences/occ-ce4cf07348c76c02.md|1.1.5]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0024698b06ff69d6.md|Issue fin-0024698b06ff69d6]]
#### Observations
- [[occurrences/occ-9ba2d61b37bd0780.md|1.2.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d8af769ae31dd3ec.md|Issue fin-d8af769ae31dd3ec]]
#### Observations
- [[occurrences/occ-ae69f0e14192bc20.md|1.2.18]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a44443f0bd1ea38f.md|Issue fin-a44443f0bd1ea38f]]
#### Observations
- [[occurrences/occ-c637d5f46446df88.md|1.2.19]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-df3c9dfbfa1594e5.md|Issue fin-df3c9dfbfa1594e5]]
#### Observations
- [[occurrences/occ-52849fd7294aabbf.md|1.2.24]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3fea236cc7d24602.md|Issue fin-3fea236cc7d24602]]
#### Observations
- [[occurrences/occ-4ec5902c1421e5bf.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b10295e4b39e7e6f.md|Issue fin-b10295e4b39e7e6f]]
#### Observations
- [[occurrences/occ-6bcc62fa62a6269e.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a4174ebf37b38624.md|Issue fin-a4174ebf37b38624]]
#### Observations
- [[occurrences/occ-1488ef28a290135f.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f990ceb47317170f.md|Issue fin-f990ceb47317170f]]
#### Observations
- [[occurrences/occ-e8ae9ff259aebf70.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cd2b0d252cc49696.md|Issue fin-cd2b0d252cc49696]]
#### Observations
- [[occurrences/occ-d036f7adf633a561.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-723c4e187e19d6cc.md|Issue fin-723c4e187e19d6cc]]
#### Observations
- [[occurrences/occ-e9a4100e741e969d.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0f69b54f4b337a38.md|Issue fin-0f69b54f4b337a38]]
#### Observations
- [[occurrences/occ-704875c033623b48.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e875a0cdafff6cab.md|Issue fin-e875a0cdafff6cab]]
#### Observations
- [[occurrences/occ-8b95238a38c192ef.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-92fa356987a8f8fa.md|Issue fin-92fa356987a8f8fa]]
#### Observations
- [[occurrences/occ-98e037c6628d4e00.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e3f91613b349e5d0.md|Issue fin-e3f91613b349e5d0]]
#### Observations
- [[occurrences/occ-4b9683fd2f63fea5.md|1.4.0]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-833c0de017db4866.md|Issue fin-833c0de017db4866]]
#### Observations
- [[occurrences/occ-dc341411d058e144.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0005417c3b6502df.md|Issue fin-0005417c3b6502df]]
#### Observations
- [[occurrences/occ-69655fe44d7b8338.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1a82a84d4b08e87b.md|Issue fin-1a82a84d4b08e87b]]
#### Observations
- [[occurrences/occ-92e66fc506c8a9ff.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3b768d15b6512f9e.md|Issue fin-3b768d15b6512f9e]]
#### Observations
- [[occurrences/occ-efc4392f01b25ac4.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5044f5eea78e0534.md|Issue fin-5044f5eea78e0534]]
#### Observations
- [[occurrences/occ-1aa25c83f2e9a4fe.md|1.6.0]]

### GET https://public-firing-range.appspot.com/angular/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3c80036d4c0e2de2.md|Issue fin-3c80036d4c0e2de2]]
#### Observations
- [[occurrences/occ-4d1ed98076be62b6.md|angular/index.html]]

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ecc480d70c8c79a8.md|Issue fin-ecc480d70c8c79a8]]
#### Observations
- [[occurrences/occ-8ddde93739dd6139.md|badscriptimport]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4c3e3640a943bf2a.md|Issue fin-4c3e3640a943bf2a]]
#### Observations
- [[occurrences/occ-bbc52b4d73968d21.md|badscriptimport/index.html]]

### GET https://public-firing-range.appspot.com/clickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5d03ecfd8b468b66.md|Issue fin-5d03ecfd8b468b66]]
#### Observations
- [[occurrences/occ-896e4c4a033aae7c.md|clickjacking]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_csp_no_frame_ancestors  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3076b788bcc6abc4.md|Issue fin-3076b788bcc6abc4]]
#### Observations
- [[occurrences/occ-145af46f1bd9c27e.md|clickjacking_csp_no_frame_ancestors]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_xfo_allowall  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c1299ddafb872c39.md|Issue fin-c1299ddafb872c39]]
#### Observations
- [[occurrences/occ-65cd3a54b4d2199c.md|clickjacking_xfo_allowall]]

### GET https://public-firing-range.appspot.com/clickjacking/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-86862d0e3018418c.md|Issue fin-86862d0e3018418c]]
#### Observations
- [[occurrences/occ-18133d808423e0f8.md|clickjacking/index.html]]

### GET https://public-firing-range.appspot.com/cors/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e5217c6b416ea7a.md|Issue fin-7e5217c6b416ea7a]]
#### Observations
- [[occurrences/occ-1eb84d89961b0922.md|cors]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowInsecureScheme  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-80258577af49ac18.md|Issue fin-80258577af49ac18]]
#### Observations
- [[occurrences/occ-148cf99b55242ffa.md|allowInsecureScheme]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-381ea5698b64c2d1.md|Issue fin-381ea5698b64c2d1]]
#### Observations
- [[occurrences/occ-b3510998a14ae0fa.md|allowNullOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a344e8103043227a.md|Issue fin-a344e8103043227a]]
#### Observations
- [[occurrences/occ-a0c34a610956a879.md|allowNullOrigin]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9066f699b4d20cbe.md|Issue fin-9066f699b4d20cbe]]
#### Observations
- [[occurrences/occ-b35a68d9a40fe8bb.md|allowOriginEndsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-363aca620e746d92.md|Issue fin-363aca620e746d92]]
#### Observations
- [[occurrences/occ-ef19424abd190e9f.md|allowOriginEndsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginProtocolDowngrade  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-948e3f63997f134a.md|Issue fin-948e3f63997f134a]]
#### Observations
- [[occurrences/occ-d73d71d4200aa578.md|allowOriginProtocolDowngrade]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginRegexDot  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3a8e624068ce2df2.md|Issue fin-3a8e624068ce2df2]]
#### Observations
- [[occurrences/occ-8984648c95bb295b.md|allowOriginRegexDot]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5b194510b07b4be8.md|Issue fin-5b194510b07b4be8]]
#### Observations
- [[occurrences/occ-efcd3d94c5691e42.md|allowOriginStartsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-13cc4ca7c50a4fe4.md|Issue fin-13cc4ca7c50a4fe4]]
#### Observations
- [[occurrences/occ-a527b0b6b0721e6e.md|allowOriginStartsWith]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a61e4a34ca2d3d00.md|Issue fin-a61e4a34ca2d3d00]]
#### Observations
- [[occurrences/occ-c5e92b04922bb967.md|dynamicAllowOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c133f859939a807c.md|Issue fin-c133f859939a807c]]
#### Observations
- [[occurrences/occ-9a9aa3a31f149c20.md|dynamicAllowOrigin]]

### GET https://public-firing-range.appspot.com/cors/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-21a79f72e7742932.md|Issue fin-21a79f72e7742932]]
#### Observations
- [[occurrences/occ-996d3a952965dec9.md|cors/index.html]]

### GET https://public-firing-range.appspot.com/dom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b0f10ff6cff479f1.md|Issue fin-b0f10ff6cff479f1]]
#### Observations
- [[occurrences/occ-bcc8ef29b8e07010.md|dom]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-911186863c8af639.md|Issue fin-911186863c8af639]]
#### Observations
- [[occurrences/occ-51aea1eedc970b0e.md|dompropagation]]

### GET https://public-firing-range.appspot.com/dom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-85393fbbd845fbb2.md|Issue fin-85393fbbd845fbb2]]
#### Observations
- [[occurrences/occ-e756940f71ed0e04.md|dom/index.html]]

### GET https://public-firing-range.appspot.com/dom/javascripturi.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc8645d8131074cc.md|Issue fin-fc8645d8131074cc]]
#### Observations
- [[occurrences/occ-5c8e7a12c783d842.md|javascripturi.html]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-43637b9a0f61fcbe.md|Issue fin-43637b9a0f61fcbe]]
#### Observations
- [[occurrences/occ-2c0de7887774d03a.md|complexMessageDocumentWriteEval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ceade1c9dcb42cc9.md|Issue fin-ceade1c9dcb42cc9]]
#### Observations
- [[occurrences/occ-4055c945b22c5de7.md|documentWrite]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-196cebe0a0f4e19b.md|Issue fin-196cebe0a0f4e19b]]
#### Observations
- [[occurrences/occ-e156e040534a1328.md|eval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9d21171f6dae3257.md|Issue fin-9d21171f6dae3257]]
#### Observations
- [[occurrences/occ-6d31a9fdd6b5ebdb.md|improperOriginValid…tialStringComparison]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-06370b2dff0c6cf3.md|Issue fin-06370b2dff0c6cf3]]
#### Observations
- [[occurrences/occ-a6b74b0c1b4f5502.md|improperOriginValidationWithRegExp]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2869611c98fc3f45.md|Issue fin-2869611c98fc3f45]]
#### Observations
- [[occurrences/occ-872e110abd9e1660.md|innerHtml]]

### GET https://public-firing-range.appspot.com/escape/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9d82b051243bc65a.md|Issue fin-9d82b051243bc65a]]
#### Observations
- [[occurrences/occ-cd8a519afad3f99a.md|escape]]

### GET https://public-firing-range.appspot.com/escape/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-582c6079bbc0e1ee.md|Issue fin-582c6079bbc0e1ee]]
#### Observations
- [[occurrences/occ-8fcd7fe4cffb6b90.md|escape/index.html]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6965892a03e02552.md|Issue fin-6965892a03e02552]]
#### Observations
- [[occurrences/occ-cd56c793efbf82c7.md|encodeURIComponent]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dc5c09c8adfe8805.md|Issue fin-dc5c09c8adfe8805]]
#### Observations
- [[occurrences/occ-29ed9101a5ded149.md|escape]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e611033134769803.md|Issue fin-e611033134769803]]
#### Observations
- [[occurrences/occ-f63f2b78ca2770d6.md|html_escape]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7833d19a1e0fc283.md|Issue fin-7833d19a1e0fc283]]
#### Observations
- [[occurrences/occ-cb46ca5ea4869e13.md|a]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-27e9fdb18178b0b6.md|Issue fin-27e9fdb18178b0b6]]
#### Observations
- [[occurrences/occ-044e59ff926e361b.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b6c074076673da32.md|Issue fin-b6c074076673da32]]
#### Observations
- [[occurrences/occ-84552126a2078108.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6aac6850e4d96c1f.md|Issue fin-6aac6850e4d96c1f]]
#### Observations
- [[occurrences/occ-cc9908cc55750cd0.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dfb4ad6941cd1d20.md|Issue fin-dfb4ad6941cd1d20]]
#### Observations
- [[occurrences/occ-d721f8365969fb7f.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9162741aa7763e58.md|Issue fin-9162741aa7763e58]]
#### Observations
- [[occurrences/occ-5f34cb8ab4619f93.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-70a3c7bfcdde9325.md|Issue fin-70a3c7bfcdde9325]]
#### Observations
- [[occurrences/occ-17f9895305d755ae.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-af5cceb45cf1e3b9.md|Issue fin-af5cceb45cf1e3b9]]
#### Observations
- [[occurrences/occ-bbce3f4ae9b93b59.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b4aa4055e1301ece.md|Issue fin-b4aa4055e1301ece]]
#### Observations
- [[occurrences/occ-c8215612390d5928.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-583cd66e96cf383f.md|Issue fin-583cd66e96cf383f]]
#### Observations
- [[occurrences/occ-dba0bdb0a0599d58.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-94a23114926c0200.md|Issue fin-94a23114926c0200]]
#### Observations
- [[occurrences/occ-35f9d3e711e64382.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec028a6de75a0ba1.md|Issue fin-ec028a6de75a0ba1]]
#### Observations
- [[occurrences/occ-eb266a3752c52841.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de1e2b30f549fbde.md|Issue fin-de1e2b30f549fbde]]
#### Observations
- [[occurrences/occ-ca46eb76b4e2b291.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1d1bc19a5051d0ce.md|Issue fin-1d1bc19a5051d0ce]]
#### Observations
- [[occurrences/occ-8b4145e804eba433.md|href]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b22c36314639f385.md|Issue fin-b22c36314639f385]]
#### Observations
- [[occurrences/occ-9de6a4031186069e.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-331009ee0bf79452.md|Issue fin-331009ee0bf79452]]
#### Observations
- [[occurrences/occ-b2ef58986deea8dd.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fb7cca8863c36618.md|Issue fin-fb7cca8863c36618]]
#### Observations
- [[occurrences/occ-aed38b3792db4bf8.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ca8bf5490e05edae.md|Issue fin-ca8bf5490e05edae]]
#### Observations
- [[occurrences/occ-bb5b83d91b44827d.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-98bb7979cde53006.md|Issue fin-98bb7979cde53006]]
#### Observations
- [[occurrences/occ-86a3781f570fd7c7.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6033033709523b9c.md|Issue fin-6033033709523b9c]]
#### Observations
- [[occurrences/occ-1ac22ca729c7ae31.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8717e80b50304b8c.md|Issue fin-8717e80b50304b8c]]
#### Observations
- [[occurrences/occ-f4cf53bd200975e3.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2c9520647f59c309.md|Issue fin-2c9520647f59c309]]
#### Observations
- [[occurrences/occ-1c7492bcf23cad36.md|textarea]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f40742e05eab014f.md|Issue fin-f40742e05eab014f]]
#### Observations
- [[occurrences/occ-703900d3edd03e1b.md|a]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ea8f2522a5a3e966.md|Issue fin-ea8f2522a5a3e966]]
#### Observations
- [[occurrences/occ-ace8ca20d1ee8fbd.md|attribute_name]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-61dedcf75496b1e4.md|Issue fin-61dedcf75496b1e4]]
#### Observations
- [[occurrences/occ-faf6b90f0a3ed70a.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-91af739623558d03.md|Issue fin-91af739623558d03]]
#### Observations
- [[occurrences/occ-5a871ee541582f4e.md|attribute_script]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-72987526b31182d7.md|Issue fin-72987526b31182d7]]
#### Observations
- [[occurrences/occ-200b2feed5d14104.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc88b0c5b7d18142.md|Issue fin-fc88b0c5b7d18142]]
#### Observations
- [[occurrences/occ-468178fa2cf1193c.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2ccb5ca847a0fd5b.md|Issue fin-2ccb5ca847a0fd5b]]
#### Observations
- [[occurrences/occ-cb768158fc10b143.md|body]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4274f98b8b1e335b.md|Issue fin-4274f98b8b1e335b]]
#### Observations
- [[occurrences/occ-872ffe1e1b882e5d.md|body_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e08152512f347e13.md|Issue fin-e08152512f347e13]]
#### Observations
- [[occurrences/occ-c969079bb146d3d2.md|css_import]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-185f762372f4bc14.md|Issue fin-185f762372f4bc14]]
#### Observations
- [[occurrences/occ-b2347e9ebc51e6e9.md|css_style]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b05516907c38df0b.md|Issue fin-b05516907c38df0b]]
#### Observations
- [[occurrences/occ-01b91b64c1d94407.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_value?q=a&escape=HTML_ESCAPE  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-493b08aa9f9c15e8.md|Issue fin-493b08aa9f9c15e8]]
#### Observations
- [[occurrences/occ-27b647fa6dd7c112.md|css_style_value]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f06de24314ce4af5.md|Issue fin-f06de24314ce4af5]]
#### Observations
- [[occurrences/occ-679349f73ee2e6e3.md|head]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6ed39e070e61c46c.md|Issue fin-6ed39e070e61c46c]]
#### Observations
- [[occurrences/occ-f363f2989e78dc52.md|href]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0752ad2422a78a2e.md|Issue fin-0752ad2422a78a2e]]
#### Observations
- [[occurrences/occ-c756102c6c744c12.md|js_assignment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-576147906e1d3578.md|Issue fin-576147906e1d3578]]
#### Observations
- [[occurrences/occ-7e075491d4cf5cb4.md|js_comment]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6117eeac7a3b3ac7.md|Issue fin-6117eeac7a3b3ac7]]
#### Observations
- [[occurrences/occ-20a860c23f392d9f.md|js_eval]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-21051a4a5b7fb3b7.md|Issue fin-21051a4a5b7fb3b7]]
#### Observations
- [[occurrences/occ-44b1408a3c682a2e.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d998cb8e91b930de.md|Issue fin-d998cb8e91b930de]]
#### Observations
- [[occurrences/occ-90cde502ad1b4078.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f27088e23b5ecfc.md|Issue fin-7f27088e23b5ecfc]]
#### Observations
- [[occurrences/occ-9cd2bf526a03dfa4.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-447c381deb93ce83.md|Issue fin-447c381deb93ce83]]
#### Observations
- [[occurrences/occ-215e210f01ed5d27.md|tagname]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eea356ccf0375310.md|Issue fin-eea356ccf0375310]]
#### Observations
- [[occurrences/occ-74904f57a341775a.md|textarea]]

### GET https://public-firing-range.appspot.com/favicon.ico  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ba50cb43b91f8c5e.md|Issue fin-ba50cb43b91f8c5e]]
#### Observations
- [[occurrences/occ-c6ad9c57542587d0.md|favicon.ico]]

### GET https://public-firing-range.appspot.com/flashinjection/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4258c96b61d00b91.md|Issue fin-4258c96b61d00b91]]
#### Observations
- [[occurrences/occ-26cc444d18b7f27a.md|flashinjection]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackIsEchoedBack?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-319bf175e00226cc.md|Issue fin-319bf175e00226cc]]
#### Observations
- [[occurrences/occ-df55e527f0d15333.md|callbackIsEchoedBack]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackParameterDoesNothing?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b3683132911e080.md|Issue fin-8b3683132911e080]]
#### Observations
- [[occurrences/occ-6a4342e462a60bbd.md|callbackParameterDoesNothing]]

### GET https://public-firing-range.appspot.com/flashinjection/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-74426559d8ea9a15.md|Issue fin-74426559d8ea9a15]]
#### Observations
- [[occurrences/occ-2a82e323d443521b.md|flashinjection/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8722f2440e27da1e.md|Issue fin-8722f2440e27da1e]]
#### Observations
- [[occurrences/occ-fdd8bf258a269449.md|insecurethirdpartyscripts]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5f57cfa2e234eb3c.md|Issue fin-5f57cfa2e234eb3c]]
#### Observations
- [[occurrences/occ-5d03c8cdd1d7cd3d.md|insecurethirdpartyscripts/index.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-34a4f4ea94db0322.md|Issue fin-34a4f4ea94db0322]]
#### Observations
- [[occurrences/occ-163ad42c5177a882.md|third_party_scripts…ource_integrity.html]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a18cb6c512db2799.md|Issue fin-a18cb6c512db2799]]
#### Observations
- [[occurrences/occ-0425d0ec6e0fd44e.md|third_party_scripts…namically_added.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d2719d45d7b7953e.md|Issue fin-d2719d45d7b7953e]]
#### Observations
- [[occurrences/occ-18fa9c0a0e11fb86.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b4942881f8a7f2bd.md|Issue fin-b4942881f8a7f2bd]]
#### Observations
- [[occurrences/occ-d142b9fe0f7cd32d.md|leakedcookie/index.html]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-67a968cea03d88be.md|Issue fin-67a968cea03d88be]]
#### Observations
- [[occurrences/occ-2498eaf335889898.md|leakedcookie]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0f6fe2779d1b57fd.md|Issue fin-0f6fe2779d1b57fd]]
#### Observations
- [[occurrences/occ-1c8f5bd3775916e7.md|leakedinresource]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ba1b9a5c946a497d.md|Issue fin-ba1b9a5c946a497d]]
#### Observations
- [[occurrences/occ-200b8f38d35c8805.md|mixedcontent]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-309454f9b0adb1d5.md|Issue fin-309454f9b0adb1d5]]
#### Observations
- [[occurrences/occ-e1e1edc7c12e2024.md|mixedcontent/index.html]]

### GET https://public-firing-range.appspot.com/redirect/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7daa3f8cfd21deed.md|Issue fin-7daa3f8cfd21deed]]
#### Observations
- [[occurrences/occ-3056726d79341692.md|redirect]]

### GET https://public-firing-range.appspot.com/redirect/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cddba6ea7dfad4ff.md|Issue fin-cddba6ea7dfad4ff]]
#### Observations
- [[occurrences/occ-4f4a4e4a885d8714.md|redirect/index.html]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-30e0d2682e2e5eec.md|Issue fin-30e0d2682e2e5eec]]
#### Observations
- [[occurrences/occ-b3ceb3c631303354.md|meta]]

### GET https://public-firing-range.appspot.com/redirect/parameter/NOSTARTSWITHJS?url=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-16be6149efdb5edc.md|Issue fin-16be6149efdb5edc]]
#### Observations
- [[occurrences/occ-44c73dcd13328721.md|NOSTARTSWITHJS]]

### GET https://public-firing-range.appspot.com/redirect/parameter?url=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5af4ab3cd34e24af.md|Issue fin-5af4ab3cd34e24af]]
#### Observations
- [[occurrences/occ-a0c0fb5a1697c87d.md|parameter]]

### GET https://public-firing-range.appspot.com/reflected/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1d46ff59e37713ad.md|Issue fin-1d46ff59e37713ad]]
#### Observations
- [[occurrences/occ-567b921a34e427f9.md|reflected]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7bcd77e145889989.md|Issue fin-7bcd77e145889989]]
#### Observations
- [[occurrences/occ-98f75a7ff647e369.md|json]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/plaintext?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-779ef6249e56b738.md|Issue fin-779ef6249e56b738]]
#### Observations
- [[occurrences/occ-5c53b137242ce33d.md|plaintext]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5da0fbf97c3c89a3.md|Issue fin-5da0fbf97c3c89a3]]
#### Observations
- [[occurrences/occ-02e3d3d9fa6e9791.md|DOUBLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8c9c22c7517d85c6.md|Issue fin-8c9c22c7517d85c6]]
#### Observations
- [[occurrences/occ-230ed7ba6e079d40.md|SINGLE_QUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-856f1518c2caad10.md|Issue fin-856f1518c2caad10]]
#### Observations
- [[occurrences/occ-b2154d3ba94035b3.md|UNQUOTED_ATTRIBUTE]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6a94a3c8e4a65bb8.md|Issue fin-6a94a3c8e4a65bb8]]
#### Observations
- [[occurrences/occ-baa3d3c6b9285ce0.md|DoubleQuoteSinglequote]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8a4fd7d689886476.md|Issue fin-8a4fd7d689886476]]
#### Observations
- [[occurrences/occ-af2b6dfbe66c8d3e.md|SpaceDoubleQuoteSlashEquals]]

### GET https://public-firing-range.appspot.com/reflected/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9d4df3ef133a5eb9.md|Issue fin-9d4df3ef133a5eb9]]
#### Observations
- [[occurrences/occ-47a811423e178c6a.md|reflected/index.html]]

### GET https://public-firing-range.appspot.com/reflected/jsoncallback  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-53603590eaac8ca3.md|Issue fin-53603590eaac8ca3]]
#### Observations
- [[occurrences/occ-fffc43f2b7d11421.md|jsoncallback]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-666c578101beef40.md|Issue fin-666c578101beef40]]
#### Observations
- [[occurrences/occ-d426fdceeadbd615.md|attribute_name]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f244d511a576cf52.md|Issue fin-f244d511a576cf52]]
#### Observations
- [[occurrences/occ-e4734d31cea47065.md|attribute_quoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6d4e3a0045f9e274.md|Issue fin-6d4e3a0045f9e274]]
#### Observations
- [[occurrences/occ-014fd1074430abdc.md|attribute_script]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-32bb1a837cba8e14.md|Issue fin-32bb1a837cba8e14]]
#### Observations
- [[occurrences/occ-26527b1ffa1b05e5.md|attribute_singlequoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-398bfb8b5e205ee9.md|Issue fin-398bfb8b5e205ee9]]
#### Observations
- [[occurrences/occ-6f0f08bbbb92e14a.md|attribute_unquoted]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/400?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b6b37318b99712a.md|Issue fin-8b6b37318b99712a]]
#### Observations
- [[occurrences/occ-701e790d6c6f826c.md|400]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/401?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0884b7e7715bcd45.md|Issue fin-0884b7e7715bcd45]]
#### Observations
- [[occurrences/occ-9dfc825c8bb9f107.md|401]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/403?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-370769f008f47949.md|Issue fin-370769f008f47949]]
#### Observations
- [[occurrences/occ-7a10f9fd60af280c.md|403]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/404?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1f2cde7977b256b4.md|Issue fin-1f2cde7977b256b4]]
#### Observations
- [[occurrences/occ-ab8a30c6bb5a2706.md|404]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body/500?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-738691c0adc249b8.md|Issue fin-738691c0adc249b8]]
#### Observations
- [[occurrences/occ-5a6192283c9f33ba.md|500]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9991aa1bae653e5d.md|Issue fin-9991aa1bae653e5d]]
#### Observations
- [[occurrences/occ-bce73c75bd1197c6.md|body]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-62085a73580cfa97.md|Issue fin-62085a73580cfa97]]
#### Observations
- [[occurrences/occ-f94c34e93960ca30.md|body_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d03076bd5677d707.md|Issue fin-d03076bd5677d707]]
#### Observations
- [[occurrences/occ-bbac1e5a4dbc8613.md|css_style]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b5eaf3f3d6243813.md|Issue fin-b5eaf3f3d6243813]]
#### Observations
- [[occurrences/occ-de406714d9db5ae5.md|css_style_font_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f1e5e4ed9025f325.md|Issue fin-f1e5e4ed9025f325]]
#### Observations
- [[occurrences/occ-948d1899417fb8dd.md|css_style_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/form  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-219eb7f9ac8ee411.md|Issue fin-219eb7f9ac8ee411]]
#### Observations
- [[occurrences/occ-81d8f5060496827a.md|form]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6e14825caa6dc31a.md|Issue fin-6e14825caa6dc31a]]
#### Observations
- [[occurrences/occ-2a16e830b8106b8f.md|head]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d53d26e62b79dfa4.md|Issue fin-d53d26e62b79dfa4]]
#### Observations
- [[occurrences/occ-429ccf3b33e68d6f.md|iframe_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8a440e0e098d4159.md|Issue fin-8a440e0e098d4159]]
#### Observations
- [[occurrences/occ-675df3c2da6a1b24.md|iframe_srcdoc]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4282173e57fa54a5.md|Issue fin-4282173e57fa54a5]]
#### Observations
- [[occurrences/occ-4c88f94eba462f17.md|js_assignment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-01524b109e78db16.md|Issue fin-01524b109e78db16]]
#### Observations
- [[occurrences/occ-8380a007a93d25c9.md|js_comment]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef0823d9fa4507f9.md|Issue fin-ef0823d9fa4507f9]]
#### Observations
- [[occurrences/occ-5178b3ddad1f17e0.md|js_eval]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-91849c46ce5c5268.md|Issue fin-91849c46ce5c5268]]
#### Observations
- [[occurrences/occ-898ad9494f4bf4d2.md|js_quoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f83fb5b2ba01f591.md|Issue fin-f83fb5b2ba01f591]]
#### Observations
- [[occurrences/occ-f43882f8d3f3b376.md|js_singlequoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-deb7ba8c971dea17.md|Issue fin-deb7ba8c971dea17]]
#### Observations
- [[occurrences/occ-67bf59d013bb8a36.md|js_slashquoted_string]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-feb5446f324f99d4.md|Issue fin-feb5446f324f99d4]]
#### Observations
- [[occurrences/occ-00536e00682dbfc0.md|json]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5e77922da6248c91.md|Issue fin-5e77922da6248c91]]
#### Observations
- [[occurrences/occ-8e8fea4b21054aac.md|noscript]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-df221d2adc6882e5.md|Issue fin-df221d2adc6882e5]]
#### Observations
- [[occurrences/occ-a986f23e0941ddaa.md|style_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-63db3c491ac39c8e.md|Issue fin-63db3c491ac39c8e]]
#### Observations
- [[occurrences/occ-6d6f211f51591f88.md|tagname]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-591524d293f05291.md|Issue fin-591524d293f05291]]
#### Observations
- [[occurrences/occ-2f8f2e548efd9afc.md|textarea]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b1c3df45e80c653e.md|Issue fin-b1c3df45e80c653e]]
#### Observations
- [[occurrences/occ-a5fcece002e714ee.md|textarea_attribute_value]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cca99f31d122183e.md|Issue fin-cca99f31d122183e]]
#### Observations
- [[occurrences/occ-e38e6ba160f96d56.md|title]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-56a5f867e7c90c53.md|Issue fin-56a5f867e7c90c53]]
#### Observations
- [[occurrences/occ-bb3110e6934adecf.md|css_import]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3252fd9c1186d937.md|Issue fin-3252fd9c1186d937]]
#### Observations
- [[occurrences/occ-f6e8aa03c858d2a4.md|href]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-19625f69ec0b2b7b.md|Issue fin-19625f69ec0b2b7b]]
#### Observations
- [[occurrences/occ-31d0cae3487a8784.md|object_data]]

### GET https://public-firing-range.appspot.com/reflected/url/object_param?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f96e431f7382b80c.md|Issue fin-f96e431f7382b80c]]
#### Observations
- [[occurrences/occ-75ff32c777439ed1.md|object_param]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6fa5308d157558ec.md|Issue fin-6fa5308d157558ec]]
#### Observations
- [[occurrences/occ-29323a49ef565bf2.md|script_src]]

### GET https://public-firing-range.appspot.com/remoteinclude/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5cadee243cd238f2.md|Issue fin-5cadee243cd238f2]]
#### Observations
- [[occurrences/occ-8e42606d4b2fbd11.md|remoteinclude]]

### GET https://public-firing-range.appspot.com/remoteinclude/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7fcb8e1030cb71a6.md|Issue fin-7fcb8e1030cb71a6]]
#### Observations
- [[occurrences/occ-5e689eb4eaaa904e.md|remoteinclude/index.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ca4cf1924cca5401.md|Issue fin-ca4cf1924cca5401]]
#### Observations
- [[occurrences/occ-3e80a78f61ad9682.md|object_hash.html]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f5b08d8cd22a3d17.md|Issue fin-f5b08d8cd22a3d17]]
#### Observations
- [[occurrences/occ-939c85111727ccb2.md|application_x-shockwave-flash]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-951fc75bdbf97b43.md|Issue fin-951fc75bdbf97b43]]
#### Observations
- [[occurrences/occ-49d596297064f2e4.md|object_raw]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6787d0fc50c09d13.md|Issue fin-6787d0fc50c09d13]]
#### Observations
- [[occurrences/occ-7d10ac3cdd8b79d3.md|script]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6e56ae71b015a525.md|Issue fin-6e56ae71b015a525]]
#### Observations
- [[occurrences/occ-d6f3afc63953aa4b.md|script_hash.html]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ab61bf26b1f61399.md|Issue fin-ab61bf26b1f61399]]
#### Observations
- [[occurrences/occ-0c2be17f467913b9.md|reverseclickjacking]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-38ab75546c78552d.md|Issue fin-38ab75546c78552d]]
#### Observations
- [[occurrences/occ-860b066cff7f2e8e.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a8a5ceab219095c3.md|Issue fin-a8a5ceab219095c3]]
#### Observations
- [[occurrences/occ-ec1196a711268b70.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-28218040c3554af8.md|Issue fin-28218040c3554af8]]
#### Observations
- [[occurrences/occ-3fecd1a94d146e46.md|InCallback]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ce652bab382afbc0.md|Issue fin-ce652bab382afbc0]]
#### Observations
- [[occurrences/occ-11cefb58eb32c34d.md|OtherParameter]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-62e6448662c9c20a.md|Issue fin-62e6448662c9c20a]]
#### Observations
- [[occurrences/occ-7262f3c7aa2c4586.md|stricttransportsecurity]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_includesubdomains_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-15761bbc67e0404c.md|Issue fin-15761bbc67e0404c]]
#### Observations
- [[occurrences/occ-38f2cdb3c3ebd02f.md|hsts_includesubdomains_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-23ffb3372c2e1a6d.md|Issue fin-23ffb3372c2e1a6d]]
#### Observations
- [[occurrences/occ-7f6b07a3cc13704a.md|hsts_max_age_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_too_low  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d45faf9a3d4509e0.md|Issue fin-d45faf9a3d4509e0]]
#### Observations
- [[occurrences/occ-4090ddb19b4e232a.md|hsts_max_age_too_low]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9a729d6514a93da1.md|Issue fin-9a729d6514a93da1]]
#### Observations
- [[occurrences/occ-d6e9a6e5143f8767.md|hsts_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_preload_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d6fef6df3cd413e7.md|Issue fin-d6fef6df3cd413e7]]
#### Observations
- [[occurrences/occ-b10dfad6be8fb5ed.md|hsts_preload_missing]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-94a9869c26d9ab15.md|Issue fin-94a9869c26d9ab15]]
#### Observations
- [[occurrences/occ-a5702c51307ad533.md|stricttransportsecurity/index.html]]

### GET https://public-firing-range.appspot.com/tags/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9fbe4d9e66d66f9e.md|Issue fin-9fbe4d9e66d66f9e]]
#### Observations
- [[occurrences/occ-83ce7d91c00f202f.md|tags]]

### GET https://public-firing-range.appspot.com/tags/expression?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8452968f0c1035a9.md|Issue fin-8452968f0c1035a9]]
#### Observations
- [[occurrences/occ-f502fb1acc4be499.md|expression]]

### GET https://public-firing-range.appspot.com/tags/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0072e1a0f3ac9296.md|Issue fin-0072e1a0f3ac9296]]
#### Observations
- [[occurrences/occ-7057dcc8e3a6f897.md|tags/index.html]]

### GET https://public-firing-range.appspot.com/tags/multiline?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e00ec388a34c8b1.md|Issue fin-7e00ec388a34c8b1]]
#### Observations
- [[occurrences/occ-7ee29120bbaeb882.md|multiline]]

### GET https://public-firing-range.appspot.com/tags/tag/a/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a650161ed4e72e2a.md|Issue fin-a650161ed4e72e2a]]
#### Observations
- [[occurrences/occ-46a40cb66365c46a.md|href]]

### GET https://public-firing-range.appspot.com/tags/tag/a/style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-90b6e9f024be0867.md|Issue fin-90b6e9f024be0867]]
#### Observations
- [[occurrences/occ-921dccf601df031a.md|style]]

### GET https://public-firing-range.appspot.com/tags/tag/body/onload?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a7e1a0a0779af5e5.md|Issue fin-a7e1a0a0779af5e5]]
#### Observations
- [[occurrences/occ-1f6d8d720eb3b822.md|onload]]

### GET https://public-firing-range.appspot.com/tags/tag/div/style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6cc3a0b6774a76c0.md|Issue fin-6cc3a0b6774a76c0]]
#### Observations
- [[occurrences/occ-218738508ce6b19d.md|style]]

### GET https://public-firing-range.appspot.com/tags/tag/div?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b75ed5c11453bfef.md|Issue fin-b75ed5c11453bfef]]
#### Observations
- [[occurrences/occ-6fd1f77ea77f17f7.md|div]]

### GET https://public-firing-range.appspot.com/tags/tag/iframe?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b63fc9d74c08d22c.md|Issue fin-b63fc9d74c08d22c]]
#### Observations
- [[occurrences/occ-1316107df9bd8116.md|iframe]]

### GET https://public-firing-range.appspot.com/tags/tag/img?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6a14589aa7a9c5f4.md|Issue fin-6a14589aa7a9c5f4]]
#### Observations
- [[occurrences/occ-ba043ed463e7eb57.md|img]]

### GET https://public-firing-range.appspot.com/tags/tag/meta?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3d9a07b983908c6f.md|Issue fin-3d9a07b983908c6f]]
#### Observations
- [[occurrences/occ-13f13f0551768ac2.md|meta]]

### GET https://public-firing-range.appspot.com/tags/tag/script/src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4d77dea999a744ab.md|Issue fin-4d77dea999a744ab]]
#### Observations
- [[occurrences/occ-88635e70951cc610.md|src]]

### GET https://public-firing-range.appspot.com/tags/tag/style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e3ed8434b297fdb2.md|Issue fin-e3ed8434b297fdb2]]
#### Observations
- [[occurrences/occ-fc1d26aa8c628e0a.md|style]]

### GET https://public-firing-range.appspot.com/tags/tag?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-240a4b4ab8714222.md|Issue fin-240a4b4ab8714222]]
#### Observations
- [[occurrences/occ-b7c3b530aa63c65a.md|tag]]

### GET https://public-firing-range.appspot.com/urldom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-546b0b70fa204ea3.md|Issue fin-546b0b70fa204ea3]]
#### Observations
- [[occurrences/occ-442a477561469797.md|urldom]]

### GET https://public-firing-range.appspot.com/urldom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-32746b5e112fc8b2.md|Issue fin-32746b5e112fc8b2]]
#### Observations
- [[occurrences/occ-357cf77762ae7151.md|urldom/index.html]]

### GET https://public-firing-range.appspot.com/urldom/jsonp?callback=foo  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f70879d420e3e00a.md|Issue fin-f70879d420e3e00a]]
#### Observations
- [[occurrences/occ-7f18dbe417dfcbf6.md|jsonp]]

### GET https://public-firing-range.appspot.com/urldom/jsonp?callback=foobar  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-685c7b95d85440a8.md|Issue fin-685c7b95d85440a8]]
#### Observations
- [[occurrences/occ-3ffed2942461d493.md|jsonp]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_domain  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5043e6d19480aa90.md|Issue fin-5043e6d19480aa90]]
#### Observations
- [[occurrences/occ-4aca821682745ea8.md|script.src.partial_domain]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_query  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-185b70f832199c37.md|Issue fin-185b70f832199c37]]
#### Observations
- [[occurrences/occ-1a0ffa5611df77bc.md|script.src.partial_query]]

### GET https://public-firing-range.appspot.com/urldom/location/search/area.href?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a1eab3afdc98ccde.md|Issue fin-a1eab3afdc98ccde]]
#### Observations
- [[occurrences/occ-bdf098929340d4a4.md|area.href]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-145ba8e53af221bf.md|Issue fin-145ba8e53af221bf]]
#### Observations
- [[occurrences/occ-e5076284c343beae.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d51da73977959718.md|Issue fin-d51da73977959718]]
#### Observations
- [[occurrences/occ-4d052bba1c55d2a8.md|button.formaction]]

### GET https://public-firing-range.appspot.com/urldom/location/search/frame.src?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0c1c3b86ce1af17d.md|Issue fin-0c1c3b86ce1af17d]]
#### Observations
- [[occurrences/occ-7858f156c8984813.md|frame.src]]

### GET https://public-firing-range.appspot.com/urldom/location/search/location.assign?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-71b2991a8be62f27.md|Issue fin-71b2991a8be62f27]]
#### Observations
- [[occurrences/occ-3774778d07d98f9b.md|location.assign]]

### GET https://public-firing-range.appspot.com/urldom/location/search/svg.a?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-faceb73f5d893de1.md|Issue fin-faceb73f5d893de1]]
#### Observations
- [[occurrences/occ-e3153ab0031fc66e.md|svg.a]]

### GET https://public-firing-range.appspot.com/urldom/redirect?url=http://example.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-310b535f21b9b76e.md|Issue fin-310b535f21b9b76e]]
#### Observations
- [[occurrences/occ-6cf0713d3d57565a.md|redirect]]

### GET https://public-firing-range.appspot.com/urldom/script.js  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b98baeb19d11c3e0.md|Issue fin-b98baeb19d11c3e0]]
#### Observations
- [[occurrences/occ-a45b3a1831f7e3e1.md|script.js]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d8218d47deb90fb3.md|Issue fin-d8218d47deb90fb3]]
#### Observations
- [[occurrences/occ-19f9301fece434f5.md|vulnerablelibraries]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-48d02cde77356f91.md|Issue fin-48d02cde77356f91]]
#### Observations
- [[occurrences/occ-e03d114305372adb.md|vulnerablelibraries/index.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ae2cc1f6e216afd3.md|Issue fin-ae2cc1f6e216afd3]]
#### Observations
- [[occurrences/occ-3a20fbabd8f3a151.md|jquery.html]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/x  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-072940ff17b6828c.md|Issue fin-072940ff17b6828c]]
#### Observations
- [[occurrences/occ-24648f036a7c2311.md|x]]

