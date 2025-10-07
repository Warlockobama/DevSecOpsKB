---
aliases:
  - "AC-0020"
cweId: "1021"
cweUri: "https://cwe.mitre.org/data/definitions/1021.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10020"
name: "Missing Anti-clickjacking Header"
occurrenceCount: "217"
pluginId: "10020"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "217"
wascId: "15"
---

# Missing Anti-clickjacking Header (Plugin 10020)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/AntiClickjackingScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/AntiClickjackingScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10020/

### How it detects

Passive; checks headers: X-Frame-Option; sets evidence; threshold: low

_threshold: low_

Signals:
- header:X-Frame-Option

## Remediation

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### References
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8f698f824b994b04.md|Issue fin-8f698f824b994b04]]
#### Observations
- [[occurrences/occ-56c20b8ec4ba5fd0.md|public-firing-range.appspot.com/[xfo]]]

### GET https://public-firing-range.appspot.com/address/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4610fe6cf62906e8.md|Issue fin-4610fe6cf62906e8]]
#### Observations
- [[occurrences/occ-1ce340c48822842c.md|address[xfo]]]

### GET https://public-firing-range.appspot.com/address/URL/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d475374337f38e8c.md|Issue fin-d475374337f38e8c]]
#### Observations
- [[occurrences/occ-4d1f5e5f601322af.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/address/URLUnencoded/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d6d4d5efe0609d7c.md|Issue fin-d6d4d5efe0609d7c]]
#### Observations
- [[occurrences/occ-e443e9c19932fff3.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/address/baseURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b0b44b9b67cab2d3.md|Issue fin-b0b44b9b67cab2d3]]
#### Observations
- [[occurrences/occ-3b830e52d10743a2.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/address/documentURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c75eeda278012975.md|Issue fin-c75eeda278012975]]
#### Observations
- [[occurrences/occ-c2d825107b5706b4.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/address/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4c45369ef1151d02.md|Issue fin-4c45369ef1151d02]]
#### Observations
- [[occurrences/occ-10d7d9dc3e21eb1a.md|address/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4882ca511ef5236d.md|Issue fin-4882ca511ef5236d]]
#### Observations
- [[occurrences/occ-931d2dd13e72ce34.md|assign[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-695ff298e6a890c5.md|Issue fin-695ff298e6a890c5]]
#### Observations
- [[occurrences/occ-a89340d47f6d9a69.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d7970cde2cdeac94.md|Issue fin-d7970cde2cdeac94]]
#### Observations
- [[occurrences/occ-54db67fc69121b9a.md|documentwriteln[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0dd94a2ae1bd0744.md|Issue fin-0dd94a2ae1bd0744]]
#### Observations
- [[occurrences/occ-73aeeed151f08662.md|eval[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-35807ea0611cb45c.md|Issue fin-35807ea0611cb45c]]
#### Observations
- [[occurrences/occ-93d532a900f6258b.md|formaction[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/function  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1e547bc00dd3b432.md|Issue fin-1e547bc00dd3b432]]
#### Observations
- [[occurrences/occ-6d7ef6dbeab05cca.md|function[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6bf70ffdd521d70f.md|Issue fin-6bf70ffdd521d70f]]
#### Observations
- [[occurrences/occ-05100074141acdf5.md|inlineevent[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5a621d9eaf42322c.md|Issue fin-5a621d9eaf42322c]]
#### Observations
- [[occurrences/occ-ea48aa67233c6625.md|innerHtml[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/jshref  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f96b5ba37489adde.md|Issue fin-f96b5ba37489adde]]
#### Observations
- [[occurrences/occ-c60301f719b02885.md|jshref[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickAddEventListener  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3df5dd6055514b6b.md|Issue fin-3df5dd6055514b6b]]
#### Observations
- [[occurrences/occ-b3760ae77e0428e5.md|onclickAddEventListener[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickSetAttribute  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-52fbe15b9751bc41.md|Issue fin-52fbe15b9751bc41]]
#### Observations
- [[occurrences/occ-1e696f225348240c.md|onclickSetAttribute[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-876e4c1a2bf69c53.md|Issue fin-876e4c1a2bf69c53]]
#### Observations
- [[occurrences/occ-3f0ee839d48bd2c7.md|rangeCreateContextualFragment[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ff9d8160bebf40a3.md|Issue fin-ff9d8160bebf40a3]]
#### Observations
- [[occurrences/occ-f083b364253bed9f.md|replace[xfo]]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-738f4224bd6732aa.md|Issue fin-738f4224bd6732aa]]
#### Observations
- [[occurrences/occ-eebfbbb5f89988b3.md|setTimeout[xfo]]]

### GET https://public-firing-range.appspot.com/address/location/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c79f186d0b4aa827.md|Issue fin-c79f186d0b4aa827]]
#### Observations
- [[occurrences/occ-b376ab3b72a968cd.md|assign[xfo]]]

### GET https://public-firing-range.appspot.com/address/location/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fbb2ed8f22bea4dd.md|Issue fin-fbb2ed8f22bea4dd]]
#### Observations
- [[occurrences/occ-ce8d772c82c328e1.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/address/location/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-69c05796673b3b35.md|Issue fin-69c05796673b3b35]]
#### Observations
- [[occurrences/occ-dd18e72b3629fbba.md|documentwriteln[xfo]]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1502f2624830e3af.md|Issue fin-1502f2624830e3af]]
#### Observations
- [[occurrences/occ-e4af2f27f1f2c794.md|eval[xfo]]]

### GET https://public-firing-range.appspot.com/address/location/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4047ba9a12edee0a.md|Issue fin-4047ba9a12edee0a]]
#### Observations
- [[occurrences/occ-eed0410d53447522.md|innerHtml[xfo]]]

### GET https://public-firing-range.appspot.com/address/location/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2d6154d1e2a0823d.md|Issue fin-2d6154d1e2a0823d]]
#### Observations
- [[occurrences/occ-e014117a260608ef.md|rangeCreateContextualFragment[xfo]]]

### GET https://public-firing-range.appspot.com/address/location/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b95db6b7e9b3689e.md|Issue fin-b95db6b7e9b3689e]]
#### Observations
- [[occurrences/occ-06c5eaeae73fc6db.md|replace[xfo]]]

### GET https://public-firing-range.appspot.com/address/location/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ed7f3815f64d25c8.md|Issue fin-ed7f3815f64d25c8]]
#### Observations
- [[occurrences/occ-74e5d997ede3241f.md|setTimeout[xfo]]]

### GET https://public-firing-range.appspot.com/address/locationhref/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-232c0f001236ff86.md|Issue fin-232c0f001236ff86]]
#### Observations
- [[occurrences/occ-e366b7d27609d2ea.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/address/locationpathname/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-971a9d637bffffee.md|Issue fin-971a9d637bffffee]]
#### Observations
- [[occurrences/occ-11866dfc60c3e683.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/address/locationsearch/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4902e6ab5dd2d06d.md|Issue fin-4902e6ab5dd2d06d]]
#### Observations
- [[occurrences/occ-58ba393167a9a021.md|documentwrite[xfo]]]

### GET https://public-firing-range.appspot.com/angular/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9a5c63471032f90e.md|Issue fin-9a5c63471032f90e]]
#### Observations
- [[occurrences/occ-64900f80a9dad1da.md|angular[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ace5d3be04225f30.md|Issue fin-ace5d3be04225f30]]
#### Observations
- [[occurrences/occ-2733c4f31d41265d.md|1.1.5[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-88003a6e990c670f.md|Issue fin-88003a6e990c670f]]
#### Observations
- [[occurrences/occ-1e3a100d8df9969d.md|1.2.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fbee40483144125e.md|Issue fin-fbee40483144125e]]
#### Observations
- [[occurrences/occ-69babfcdce6b58be.md|1.2.18[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dd11c624b12de1f8.md|Issue fin-dd11c624b12de1f8]]
#### Observations
- [[occurrences/occ-642af3cb040be72a.md|1.2.19[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c9ea00394f951729.md|Issue fin-c9ea00394f951729]]
#### Observations
- [[occurrences/occ-74aa2b6b4eebda07.md|1.2.24[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-11e6cdf632bdc50e.md|Issue fin-11e6cdf632bdc50e]]
#### Observations
- [[occurrences/occ-6882178d1aa51d6c.md|1.4.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f21afa3715aaf83e.md|Issue fin-f21afa3715aaf83e]]
#### Observations
- [[occurrences/occ-aeaa66836f93ca92.md|1.6.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-efbcc0d310f9a47c.md|Issue fin-efbcc0d310f9a47c]]
#### Observations
- [[occurrences/occ-b12c59aef343f2a2.md|1.4.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8428256c915053e9.md|Issue fin-8428256c915053e9]]
#### Observations
- [[occurrences/occ-2394ff1b24ff3ac9.md|1.6.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-12aa87cee0172f75.md|Issue fin-12aa87cee0172f75]]
#### Observations
- [[occurrences/occ-82bd066d4e1f9e38.md|1.4.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f79ff1db420f9049.md|Issue fin-f79ff1db420f9049]]
#### Observations
- [[occurrences/occ-1167f7efdc6f27a3.md|1.4.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2a8c47e4190293f4.md|Issue fin-2a8c47e4190293f4]]
#### Observations
- [[occurrences/occ-e6a438b97b3a0367.md|1.4.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5809ec1bb0a51b29.md|Issue fin-5809ec1bb0a51b29]]
#### Observations
- [[occurrences/occ-93c4a7b51c93bf43.md|1.4.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f52b0d58acd0d8ca.md|Issue fin-f52b0d58acd0d8ca]]
#### Observations
- [[occurrences/occ-15b27f8c3cd86460.md|1.4.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f6aea062fe49e2a2.md|Issue fin-f6aea062fe49e2a2]]
#### Observations
- [[occurrences/occ-9772febf21d01b4b.md|1.4.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8eaa47ea71ec930f.md|Issue fin-8eaa47ea71ec930f]]
#### Observations
- [[occurrences/occ-cafa503a059cb786.md|1.6.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2ee755c753a5f18c.md|Issue fin-2ee755c753a5f18c]]
#### Observations
- [[occurrences/occ-478aebc80cde9864.md|1.6.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3dd5aede7c3eafc5.md|Issue fin-3dd5aede7c3eafc5]]
#### Observations
- [[occurrences/occ-6e97b4540d7f0975.md|1.6.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a8d77fd2d14af315.md|Issue fin-a8d77fd2d14af315]]
#### Observations
- [[occurrences/occ-788431072f752466.md|1.6.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dabbeaa15a087353.md|Issue fin-dabbeaa15a087353]]
#### Observations
- [[occurrences/occ-ad34f2e46e5c23e6.md|1.6.0[xfo]]]

### GET https://public-firing-range.appspot.com/angular/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1eecce386cb6cb90.md|Issue fin-1eecce386cb6cb90]]
#### Observations
- [[occurrences/occ-26eb9dfcae91d6ad.md|angular/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c8c0d0f3d4c2f8a6.md|Issue fin-c8c0d0f3d4c2f8a6]]
#### Observations
- [[occurrences/occ-4c381b28825e9aa3.md|badscriptimport[xfo]]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f4d6e4c7c77fd03e.md|Issue fin-f4d6e4c7c77fd03e]]
#### Observations
- [[occurrences/occ-7638c3d9c0b5b350.md|badscriptimport/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/clickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cdc2a517fe5f9d49.md|Issue fin-cdc2a517fe5f9d49]]
#### Observations
- [[occurrences/occ-7cf98d4d38b269f9.md|clickjacking[xfo]]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_csp_no_frame_ancestors  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-16a9206ad8e2734e.md|Issue fin-16a9206ad8e2734e]]
#### Observations
- [[occurrences/occ-dc6cb4fe280334ac.md|clickjacking_csp_no_frame_ancestors[xfo]]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_xfo_allowall  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-68207a1cf779dbc6.md|Issue fin-68207a1cf779dbc6]]
#### Observations
- [[occurrences/occ-5476da7ad3a26a4f.md|clickjacking_xfo_allowall[xfo]]]

### GET https://public-firing-range.appspot.com/clickjacking/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4062b6a378c27e35.md|Issue fin-4062b6a378c27e35]]
#### Observations
- [[occurrences/occ-febb38ca8d05bb2d.md|clickjacking/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/cors/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-769e74094fc8321f.md|Issue fin-769e74094fc8321f]]
#### Observations
- [[occurrences/occ-7fb633b4441dd756.md|cors[xfo]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowInsecureScheme  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5e3d7df7dfae7207.md|Issue fin-5e3d7df7dfae7207]]
#### Observations
- [[occurrences/occ-6fe32a3423ddfe9c.md|allowInsecureScheme[xfo]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-97fc4ddf04c1b9be.md|Issue fin-97fc4ddf04c1b9be]]
#### Observations
- [[occurrences/occ-4d83de953877585a.md|allowNullOrigin[xfo]]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-161a7aa776d9d340.md|Issue fin-161a7aa776d9d340]]
#### Observations
- [[occurrences/occ-21eca7e46a693586.md|allowNullOrigin[xfo]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1c0fd9a524183b4f.md|Issue fin-1c0fd9a524183b4f]]
#### Observations
- [[occurrences/occ-07adfacafec3b362.md|allowOriginEndsWith[xfo]]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-284042cc53cb011e.md|Issue fin-284042cc53cb011e]]
#### Observations
- [[occurrences/occ-74fe3c054df1f014.md|allowOriginEndsWith[xfo]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginProtocolDowngrade  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-da0b20f00a7846c3.md|Issue fin-da0b20f00a7846c3]]
#### Observations
- [[occurrences/occ-7e6550d6423bcbd6.md|allowOriginProtocolDowngrade[xfo]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginRegexDot  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-060c789144eca629.md|Issue fin-060c789144eca629]]
#### Observations
- [[occurrences/occ-a4116336cba67fb5.md|allowOriginRegexDot[xfo]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e73c8931541718e.md|Issue fin-7e73c8931541718e]]
#### Observations
- [[occurrences/occ-4fbf49fe81c1111f.md|allowOriginStartsWith[xfo]]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0d0845d565b22341.md|Issue fin-0d0845d565b22341]]
#### Observations
- [[occurrences/occ-da8f07c87d77ddce.md|allowOriginStartsWith[xfo]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-96ad6b0c465fee71.md|Issue fin-96ad6b0c465fee71]]
#### Observations
- [[occurrences/occ-192844a2caf4fda4.md|dynamicAllowOrigin[xfo]]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1b16101f41ae2d60.md|Issue fin-1b16101f41ae2d60]]
#### Observations
- [[occurrences/occ-91427c84c98f9d0b.md|dynamicAllowOrigin[xfo]]]

### GET https://public-firing-range.appspot.com/cors/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3d8e4e1c342310b7.md|Issue fin-3d8e4e1c342310b7]]
#### Observations
- [[occurrences/occ-13ef26af4bd45155.md|cors/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/dom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3cc2410880eeffea.md|Issue fin-3cc2410880eeffea]]
#### Observations
- [[occurrences/occ-d34c0862bcfe0f29.md|dom[xfo]]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d3801d95a734a2b5.md|Issue fin-d3801d95a734a2b5]]
#### Observations
- [[occurrences/occ-7d01b702729d5de6.md|dompropagation[xfo]]]

### GET https://public-firing-range.appspot.com/dom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b7ba2ef9b66369b4.md|Issue fin-b7ba2ef9b66369b4]]
#### Observations
- [[occurrences/occ-5136ec96f9ab834b.md|dom/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/dom/javascripturi.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b060b6259d7d53c7.md|Issue fin-b060b6259d7d53c7]]
#### Observations
- [[occurrences/occ-3784bce2611aafad.md|javascripturi.html[xfo]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0da2dc22950a5087.md|Issue fin-0da2dc22950a5087]]
#### Observations
- [[occurrences/occ-deb6e6398666e4ae.md|complexMessageDocumentWriteEval[xfo]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fddecdc193cebac7.md|Issue fin-fddecdc193cebac7]]
#### Observations
- [[occurrences/occ-1226437b9614380a.md|documentWrite[xfo]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c01adcc39e8bd39f.md|Issue fin-c01adcc39e8bd39f]]
#### Observations
- [[occurrences/occ-4e2e93aa5ca2af17.md|eval[xfo]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4367b253d14fec14.md|Issue fin-4367b253d14fec14]]
#### Observations
- [[occurrences/occ-834ba6cd584e1ae4.md|improperOriginValid…tringComparison[xfo]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dbbca55253b4c10e.md|Issue fin-dbbca55253b4c10e]]
#### Observations
- [[occurrences/occ-1a867ea147bff677.md|improperOriginValidationWithRegExp[xfo]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-33df8609bd8e0fa6.md|Issue fin-33df8609bd8e0fa6]]
#### Observations
- [[occurrences/occ-20e700952cef26b6.md|innerHtml[xfo]]]

### GET https://public-firing-range.appspot.com/escape/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-906a17cd29d8eeeb.md|Issue fin-906a17cd29d8eeeb]]
#### Observations
- [[occurrences/occ-ebe302ba28362abd.md|escape[xfo]]]

### GET https://public-firing-range.appspot.com/escape/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bf9279b97510b640.md|Issue fin-bf9279b97510b640]]
#### Observations
- [[occurrences/occ-605ecd10d69fcbbd.md|escape/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7286fd5796c25987.md|Issue fin-7286fd5796c25987]]
#### Observations
- [[occurrences/occ-4551de257a71cc6b.md|encodeURIComponent[xfo]]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e59827af92440e4.md|Issue fin-7e59827af92440e4]]
#### Observations
- [[occurrences/occ-9c881a225bfe4f12.md|escape[xfo]]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a34beeb7d4c8cb4a.md|Issue fin-a34beeb7d4c8cb4a]]
#### Observations
- [[occurrences/occ-e1078e631baf0eef.md|html_escape[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6e089a20c9f46edf.md|Issue fin-6e089a20c9f46edf]]
#### Observations
- [[occurrences/occ-5ab0af1fe66e5504.md|attribute_name[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-94ed95190a40e11c.md|Issue fin-94ed95190a40e11c]]
#### Observations
- [[occurrences/occ-8cc95838acf0472b.md|attribute_quoted[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8753e2d07609cfb5.md|Issue fin-8753e2d07609cfb5]]
#### Observations
- [[occurrences/occ-d80ad436e774ecdb.md|attribute_script[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4a998605cbfa73e5.md|Issue fin-4a998605cbfa73e5]]
#### Observations
- [[occurrences/occ-c2cf73b68c242755.md|attribute_singlequoted[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3250ff4e43143db2.md|Issue fin-3250ff4e43143db2]]
#### Observations
- [[occurrences/occ-268dbf2af7b12e37.md|attribute_unquoted[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-636f4a1404469430.md|Issue fin-636f4a1404469430]]
#### Observations
- [[occurrences/occ-d52904fcbce29287.md|body[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-276790e93d744ebd.md|Issue fin-276790e93d744ebd]]
#### Observations
- [[occurrences/occ-71b36e4e3f9b71a4.md|body_comment[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8d6a7210bb1b8e03.md|Issue fin-8d6a7210bb1b8e03]]
#### Observations
- [[occurrences/occ-a46199f904d4a64b.md|css_import[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-641f233ea86510be.md|Issue fin-641f233ea86510be]]
#### Observations
- [[occurrences/occ-b9f29263a18c6920.md|css_style[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d35e6804ad77df93.md|Issue fin-d35e6804ad77df93]]
#### Observations
- [[occurrences/occ-410560d33190a792.md|css_style_font_value[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a3c526aba368d6fe.md|Issue fin-a3c526aba368d6fe]]
#### Observations
- [[occurrences/occ-dd3f31b80c68fffc.md|css_style_value[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6fb8704140056b74.md|Issue fin-6fb8704140056b74]]
#### Observations
- [[occurrences/occ-35679d004fd2a94c.md|head[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5ebba0614d8c208b.md|Issue fin-5ebba0614d8c208b]]
#### Observations
- [[occurrences/occ-0301c13de9278bc1.md|js_assignment[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8992ef506d2e4c97.md|Issue fin-8992ef506d2e4c97]]
#### Observations
- [[occurrences/occ-c3393fd922248fbb.md|js_comment[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8437c781fc327e0f.md|Issue fin-8437c781fc327e0f]]
#### Observations
- [[occurrences/occ-66a21f59a407fcb8.md|js_eval[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-242420ecd2d2f1a0.md|Issue fin-242420ecd2d2f1a0]]
#### Observations
- [[occurrences/occ-84eb46189d313fb0.md|js_quoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c00ad171253bcaea.md|Issue fin-c00ad171253bcaea]]
#### Observations
- [[occurrences/occ-a8cb6cff6e34f04a.md|js_singlequoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-58ed7834a7282f27.md|Issue fin-58ed7834a7282f27]]
#### Observations
- [[occurrences/occ-66867472878f1b2d.md|js_slashquoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9748c9c2dc7a3866.md|Issue fin-9748c9c2dc7a3866]]
#### Observations
- [[occurrences/occ-36c3322ee420b5a3.md|tagname[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-074a9e37d2129c50.md|Issue fin-074a9e37d2129c50]]
#### Observations
- [[occurrences/occ-c6ac1d500b9a5881.md|textarea[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5efeebb4d9b62fa4.md|Issue fin-5efeebb4d9b62fa4]]
#### Observations
- [[occurrences/occ-37833cb90430b189.md|attribute_name[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d8d9c0a6fca1a585.md|Issue fin-d8d9c0a6fca1a585]]
#### Observations
- [[occurrences/occ-01a11b03e66708a1.md|attribute_quoted[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-909e5aab8b025d99.md|Issue fin-909e5aab8b025d99]]
#### Observations
- [[occurrences/occ-ed7e1763d219521a.md|attribute_script[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e7d528f758b6ef34.md|Issue fin-e7d528f758b6ef34]]
#### Observations
- [[occurrences/occ-6096de9c1b2eebb2.md|attribute_singlequoted[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e46ada50922b44ae.md|Issue fin-e46ada50922b44ae]]
#### Observations
- [[occurrences/occ-d808d6d0da664132.md|attribute_unquoted[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7946008d457fa60c.md|Issue fin-7946008d457fa60c]]
#### Observations
- [[occurrences/occ-d4ef5f3fa439008a.md|body[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d1ddc008c50e970a.md|Issue fin-d1ddc008c50e970a]]
#### Observations
- [[occurrences/occ-be6580e3990feb99.md|body_comment[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f5f15a7a5ec70403.md|Issue fin-f5f15a7a5ec70403]]
#### Observations
- [[occurrences/occ-0b0fa05ed1c48306.md|css_import[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f5950f218ce23d0a.md|Issue fin-f5950f218ce23d0a]]
#### Observations
- [[occurrences/occ-82e55c22ac0083a1.md|css_style[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b40a3aabc8fd8bb4.md|Issue fin-b40a3aabc8fd8bb4]]
#### Observations
- [[occurrences/occ-542ba64794ba76d3.md|css_style_font_value[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_value?q=a&escape=HTML_ESCAPE  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-af253a4d1b23ba0b.md|Issue fin-af253a4d1b23ba0b]]
#### Observations
- [[occurrences/occ-1c4f172ec30c5a78.md|css_style_value[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cb89022e3cd31328.md|Issue fin-cb89022e3cd31328]]
#### Observations
- [[occurrences/occ-643f6fe73896df6e.md|head[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a865912db37ccd09.md|Issue fin-a865912db37ccd09]]
#### Observations
- [[occurrences/occ-46c2dd2d3e8f9e29.md|js_assignment[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef0023ee9f769974.md|Issue fin-ef0023ee9f769974]]
#### Observations
- [[occurrences/occ-4520ec512b0d700f.md|js_comment[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e6c6de811d463e72.md|Issue fin-e6c6de811d463e72]]
#### Observations
- [[occurrences/occ-25e936efb0ad63f2.md|js_eval[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db775a0b3923cbba.md|Issue fin-db775a0b3923cbba]]
#### Observations
- [[occurrences/occ-1bdf60bd7217b476.md|js_quoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6ddffbed51387fcc.md|Issue fin-6ddffbed51387fcc]]
#### Observations
- [[occurrences/occ-43fc04d21c78a961.md|js_singlequoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef46b30b72970ba9.md|Issue fin-ef46b30b72970ba9]]
#### Observations
- [[occurrences/occ-0afb876f45584a2a.md|js_slashquoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5db29775e0c62392.md|Issue fin-5db29775e0c62392]]
#### Observations
- [[occurrences/occ-8b34e8e7d6efdfbc.md|tagname[xfo]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-96ab803fb2e55d41.md|Issue fin-96ab803fb2e55d41]]
#### Observations
- [[occurrences/occ-186dd93940b7452d.md|textarea[xfo]]]

### GET https://public-firing-range.appspot.com/flashinjection/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d58ff60ba8126971.md|Issue fin-d58ff60ba8126971]]
#### Observations
- [[occurrences/occ-5de35ccdbee0d541.md|flashinjection[xfo]]]

### GET https://public-firing-range.appspot.com/flashinjection/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0f9b85c90d72855d.md|Issue fin-0f9b85c90d72855d]]
#### Observations
- [[occurrences/occ-76fb1d8012f40194.md|flashinjection/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a5808c50b8060f3a.md|Issue fin-a5808c50b8060f3a]]
#### Observations
- [[occurrences/occ-09e121c8afb17154.md|insecurethirdpartyscripts[xfo]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-646cce147d43dd01.md|Issue fin-646cce147d43dd01]]
#### Observations
- [[occurrences/occ-29feae277c8b40dd.md|insecurethirdpartys…ipts/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-679489ba99e7c538.md|Issue fin-679489ba99e7c538]]
#### Observations
- [[occurrences/occ-6d33a83f56194123.md|third_party_scripts…_integrity.html[xfo]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9bdf7813b093122f.md|Issue fin-9bdf7813b093122f]]
#### Observations
- [[occurrences/occ-630ce3d41d8be67b.md|third_party_scripts…ally_added.html[xfo]]]

### GET https://public-firing-range.appspot.com/leakedcookie/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f093152e09f529ae.md|Issue fin-f093152e09f529ae]]
#### Observations
- [[occurrences/occ-51be6f74fb1d3632.md|leakedcookie[xfo]]]

### GET https://public-firing-range.appspot.com/leakedcookie/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ad9aa39532a063a2.md|Issue fin-ad9aa39532a063a2]]
#### Observations
- [[occurrences/occ-47b7ee92f63abebd.md|leakedcookie/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-672e68829c0e2be6.md|Issue fin-672e68829c0e2be6]]
#### Observations
- [[occurrences/occ-72e50f449015f178.md|leakedcookie[xfo]]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8d846d4c303e33ac.md|Issue fin-8d846d4c303e33ac]]
#### Observations
- [[occurrences/occ-b65401916d9adfd7.md|leakedinresource[xfo]]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cf96c3cdcb66853b.md|Issue fin-cf96c3cdcb66853b]]
#### Observations
- [[occurrences/occ-24c0961f228d9d46.md|mixedcontent[xfo]]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-784bf8389da43320.md|Issue fin-784bf8389da43320]]
#### Observations
- [[occurrences/occ-99d53c0155849c3e.md|mixedcontent/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/redirect/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-697b8b69dd9ac01e.md|Issue fin-697b8b69dd9ac01e]]
#### Observations
- [[occurrences/occ-e0fcb6326aa5900c.md|redirect[xfo]]]

### GET https://public-firing-range.appspot.com/redirect/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-99f45bd7d5c3de4c.md|Issue fin-99f45bd7d5c3de4c]]
#### Observations
- [[occurrences/occ-c6f5cde219f25645.md|redirect/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-169eb916a1d1d373.md|Issue fin-169eb916a1d1d373]]
#### Observations
- [[occurrences/occ-ca9e0531bbe0a1aa.md|meta[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-016cffca8e42794c.md|Issue fin-016cffca8e42794c]]
#### Observations
- [[occurrences/occ-ed42d3bd6f9edd28.md|reflected[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f1a597e06e9bd4a3.md|Issue fin-f1a597e06e9bd4a3]]
#### Observations
- [[occurrences/occ-aa2e820da2371cc0.md|DOUBLE_QUOTED_ATTRIBUTE[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8d49ed48f6c72e23.md|Issue fin-8d49ed48f6c72e23]]
#### Observations
- [[occurrences/occ-2b5e4c2f5ba4c280.md|SINGLE_QUOTED_ATTRIBUTE[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-57775184b7fb92c4.md|Issue fin-57775184b7fb92c4]]
#### Observations
- [[occurrences/occ-d71bce50951d1387.md|UNQUOTED_ATTRIBUTE[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-feb4c10ce70a3f55.md|Issue fin-feb4c10ce70a3f55]]
#### Observations
- [[occurrences/occ-1268444362ccdacc.md|DoubleQuoteSinglequote[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a7e6cc81c391ceac.md|Issue fin-a7e6cc81c391ceac]]
#### Observations
- [[occurrences/occ-407555f2ed81a753.md|SpaceDoubleQuoteSlashEquals[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9ae48c00c63a6893.md|Issue fin-9ae48c00c63a6893]]
#### Observations
- [[occurrences/occ-2ff20853d39bb669.md|reflected/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef481cb4b61cd1a3.md|Issue fin-ef481cb4b61cd1a3]]
#### Observations
- [[occurrences/occ-4a7c40a7fffd83df.md|attribute_name[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9dc3e6b8d2cfe9d6.md|Issue fin-9dc3e6b8d2cfe9d6]]
#### Observations
- [[occurrences/occ-fa81f72b0cf248d2.md|attribute_quoted[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2b6113b74e4e73db.md|Issue fin-2b6113b74e4e73db]]
#### Observations
- [[occurrences/occ-fe684974cd72e500.md|attribute_script[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9806b0aa44cd207a.md|Issue fin-9806b0aa44cd207a]]
#### Observations
- [[occurrences/occ-a41ab6b7bfb14354.md|attribute_singlequoted[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-243fa7223ac4f302.md|Issue fin-243fa7223ac4f302]]
#### Observations
- [[occurrences/occ-17601b7a28107fb5.md|attribute_unquoted[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6099bf1fcea1963b.md|Issue fin-6099bf1fcea1963b]]
#### Observations
- [[occurrences/occ-35e4b3151b66e2e5.md|body[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3be0f736422371ab.md|Issue fin-3be0f736422371ab]]
#### Observations
- [[occurrences/occ-16825af6b493e114.md|body_comment[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a195d58240125aa8.md|Issue fin-a195d58240125aa8]]
#### Observations
- [[occurrences/occ-236d78c50016257a.md|css_style[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e451a1460cd41dc9.md|Issue fin-e451a1460cd41dc9]]
#### Observations
- [[occurrences/occ-954e1bb8a5553b83.md|css_style_font_value[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-13ef8410280939b0.md|Issue fin-13ef8410280939b0]]
#### Observations
- [[occurrences/occ-7c9fc8a3958f5440.md|css_style_value[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/form  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3ef40fed1da95922.md|Issue fin-3ef40fed1da95922]]
#### Observations
- [[occurrences/occ-ce1ecb6117c836e1.md|form[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-baba35d1cb906d58.md|Issue fin-baba35d1cb906d58]]
#### Observations
- [[occurrences/occ-085bb88f47d66e14.md|head[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eaa34cce53ae58ca.md|Issue fin-eaa34cce53ae58ca]]
#### Observations
- [[occurrences/occ-5233c71519a8f977.md|iframe_attribute_value[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e74684c35af6bb44.md|Issue fin-e74684c35af6bb44]]
#### Observations
- [[occurrences/occ-ea618aead73910fb.md|iframe_srcdoc[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a9e40103ab01d04d.md|Issue fin-a9e40103ab01d04d]]
#### Observations
- [[occurrences/occ-4c6dde2a382ec633.md|js_assignment[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5d39bb14f385600e.md|Issue fin-5d39bb14f385600e]]
#### Observations
- [[occurrences/occ-41d53fafe5ef29c5.md|js_comment[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9594895f22e5920b.md|Issue fin-9594895f22e5920b]]
#### Observations
- [[occurrences/occ-3a5bdf21720135b8.md|js_eval[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5cf382479d2f4e7b.md|Issue fin-5cf382479d2f4e7b]]
#### Observations
- [[occurrences/occ-2ded977cf3b5ffe0.md|js_quoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4f13eb561cf1e0a1.md|Issue fin-4f13eb561cf1e0a1]]
#### Observations
- [[occurrences/occ-46720e3c8f6dc5b5.md|js_singlequoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-521ae23a8e104ccd.md|Issue fin-521ae23a8e104ccd]]
#### Observations
- [[occurrences/occ-04814624d0e578eb.md|js_slashquoted_string[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-58629d20ea83d253.md|Issue fin-58629d20ea83d253]]
#### Observations
- [[occurrences/occ-c73e75bc63a00dae.md|json[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7ffcaa14f5c7fa7c.md|Issue fin-7ffcaa14f5c7fa7c]]
#### Observations
- [[occurrences/occ-648eb4793382f117.md|noscript[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a274e838fe898638.md|Issue fin-a274e838fe898638]]
#### Observations
- [[occurrences/occ-04150a5af7c2f2b0.md|style_attribute_value[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fa47b773ce70f694.md|Issue fin-fa47b773ce70f694]]
#### Observations
- [[occurrences/occ-e65189a167e3466d.md|tagname[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e3b482f6d9a1aa08.md|Issue fin-e3b482f6d9a1aa08]]
#### Observations
- [[occurrences/occ-e998c9633c9044dc.md|textarea[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eec3a00636425443.md|Issue fin-eec3a00636425443]]
#### Observations
- [[occurrences/occ-515a0024cbf2a2f3.md|textarea_attribute_value[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-830809e104cfb959.md|Issue fin-830809e104cfb959]]
#### Observations
- [[occurrences/occ-a65c6f29e360c424.md|title[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d919a1159d9f190c.md|Issue fin-d919a1159d9f190c]]
#### Observations
- [[occurrences/occ-1d4dfc9a8dfa6c05.md|css_import[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5bcd398ae6aa63f5.md|Issue fin-5bcd398ae6aa63f5]]
#### Observations
- [[occurrences/occ-d5c87a804edf0c51.md|href[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-01d9c935b71c631c.md|Issue fin-01d9c935b71c631c]]
#### Observations
- [[occurrences/occ-02f06d48de2eb102.md|object_data[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/url/object_param?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6ffff910e78dce2c.md|Issue fin-6ffff910e78dce2c]]
#### Observations
- [[occurrences/occ-a0d49e54c7b77319.md|object_param[xfo]]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3efb925151722f92.md|Issue fin-3efb925151722f92]]
#### Observations
- [[occurrences/occ-075aedcf20623543.md|script_src[xfo]]]

### GET https://public-firing-range.appspot.com/remoteinclude/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ad0e3a8c0e4d578.md|Issue fin-0ad0e3a8c0e4d578]]
#### Observations
- [[occurrences/occ-b9c86b6fa57241f1.md|remoteinclude[xfo]]]

### GET https://public-firing-range.appspot.com/remoteinclude/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-78fac57bd42ce74f.md|Issue fin-78fac57bd42ce74f]]
#### Observations
- [[occurrences/occ-e2d01d1ba2b82c66.md|remoteinclude/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ad9255d013b14edf.md|Issue fin-ad9255d013b14edf]]
#### Observations
- [[occurrences/occ-7a6d7245bdab9de7.md|object_hash.html[xfo]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2ea775e711096f58.md|Issue fin-2ea775e711096f58]]
#### Observations
- [[occurrences/occ-a3c00139c638183b.md|application_x-shockwave-flash[xfo]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f9fc92aabd6d7cdd.md|Issue fin-f9fc92aabd6d7cdd]]
#### Observations
- [[occurrences/occ-c1d4d4e890e7c699.md|object_raw[xfo]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f6aa09000fcda341.md|Issue fin-f6aa09000fcda341]]
#### Observations
- [[occurrences/occ-e95a3b3a50ebae62.md|script[xfo]]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6fe2deced1b2ef21.md|Issue fin-6fe2deced1b2ef21]]
#### Observations
- [[occurrences/occ-43ff250b702229b7.md|script_hash.html[xfo]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3dbf69572f810e71.md|Issue fin-3dbf69572f810e71]]
#### Observations
- [[occurrences/occ-ee6fca13323ad850.md|reverseclickjacking[xfo]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6cd26aa71516e9b6.md|Issue fin-6cd26aa71516e9b6]]
#### Observations
- [[occurrences/occ-c875d5cda16820e1.md|InCallback[xfo]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5222ad7a1a6e73e0.md|Issue fin-5222ad7a1a6e73e0]]
#### Observations
- [[occurrences/occ-b445af2dc9323fb7.md|OtherParameter[xfo]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-929c6fa161e95259.md|Issue fin-929c6fa161e95259]]
#### Observations
- [[occurrences/occ-a8696126516bcab7.md|InCallback[xfo]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-20363fe350e548fc.md|Issue fin-20363fe350e548fc]]
#### Observations
- [[occurrences/occ-644249da110a5241.md|OtherParameter[xfo]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-da3fe806e470cc89.md|Issue fin-da3fe806e470cc89]]
#### Observations
- [[occurrences/occ-fa39020566235f32.md|stricttransportsecurity[xfo]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_includesubdomains_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ac1b5ebe678553c2.md|Issue fin-ac1b5ebe678553c2]]
#### Observations
- [[occurrences/occ-471813e68e736c9a.md|hsts_includesubdomains_missing[xfo]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5571faeba5d1bd6b.md|Issue fin-5571faeba5d1bd6b]]
#### Observations
- [[occurrences/occ-c2bf537a1fa66b3d.md|hsts_max_age_missing[xfo]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_too_low  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b10c9225a985a0f5.md|Issue fin-b10c9225a985a0f5]]
#### Observations
- [[occurrences/occ-283709b943eefc7b.md|hsts_max_age_too_low[xfo]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f6f577536f0eb7ff.md|Issue fin-f6f577536f0eb7ff]]
#### Observations
- [[occurrences/occ-c001051394699636.md|hsts_missing[xfo]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_preload_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e2e032eb3a5445eb.md|Issue fin-e2e032eb3a5445eb]]
#### Observations
- [[occurrences/occ-2d2b9c59b03e2c83.md|hsts_preload_missing[xfo]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1a6bcedb4ef2b33b.md|Issue fin-1a6bcedb4ef2b33b]]
#### Observations
- [[occurrences/occ-59aaa8b88fcf0443.md|stricttransportsecurity/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/tags/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1366a6d3beed6a3e.md|Issue fin-1366a6d3beed6a3e]]
#### Observations
- [[occurrences/occ-6a78b7c682ed4bdf.md|tags[xfo]]]

### GET https://public-firing-range.appspot.com/tags/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-610fbe5d088356b2.md|Issue fin-610fbe5d088356b2]]
#### Observations
- [[occurrences/occ-b6f1470a8e09204b.md|tags/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/tags/multiline?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-62e541d6ad61ab51.md|Issue fin-62e541d6ad61ab51]]
#### Observations
- [[occurrences/occ-df0387ac1b543de3.md|multiline[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-762fa12289f1f648.md|Issue fin-762fa12289f1f648]]
#### Observations
- [[occurrences/occ-8e853b41dee358ac.md|urldom[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9af9020c6017e798.md|Issue fin-9af9020c6017e798]]
#### Observations
- [[occurrences/occ-13e322dd9d64e99b.md|urldom/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_domain  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a20f5eca61647730.md|Issue fin-a20f5eca61647730]]
#### Observations
- [[occurrences/occ-f44bc1e5e6a19c70.md|script.src.partial_domain[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_query  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-64dec875827f37a1.md|Issue fin-64dec875827f37a1]]
#### Observations
- [[occurrences/occ-8d9f2845f9d82f9d.md|script.src.partial_query[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/area.href?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b726bfa6e48a4833.md|Issue fin-b726bfa6e48a4833]]
#### Observations
- [[occurrences/occ-1b3d918083dd6ac5.md|area.href[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-45eb1954d20bcae7.md|Issue fin-45eb1954d20bcae7]]
#### Observations
- [[occurrences/occ-3efe307168097b66.md|button.formaction[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c6b2b0374242fe81.md|Issue fin-c6b2b0374242fe81]]
#### Observations
- [[occurrences/occ-1e074b93216ba64a.md|button.formaction[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/frame.src?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-31ef17ae9afa5126.md|Issue fin-31ef17ae9afa5126]]
#### Observations
- [[occurrences/occ-ba066b1a9de68356.md|frame.src[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/location.assign?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0bcf5166e3fd521e.md|Issue fin-0bcf5166e3fd521e]]
#### Observations
- [[occurrences/occ-b8048c38732ceb1b.md|location.assign[xfo]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/svg.a?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-92df9e7ad764187f.md|Issue fin-92df9e7ad764187f]]
#### Observations
- [[occurrences/occ-f6e7c7e736afde69.md|svg.a[xfo]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-138430209eca09d0.md|Issue fin-138430209eca09d0]]
#### Observations
- [[occurrences/occ-a8b42fe2f5714fa3.md|vulnerablelibraries[xfo]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cab6ce14df401150.md|Issue fin-cab6ce14df401150]]
#### Observations
- [[occurrences/occ-76307fbf54bda2e9.md|vulnerablelibraries/index.html[xfo]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3ae70a00fa3ba45c.md|Issue fin-3ae70a00fa3ba45c]]
#### Observations
- [[occurrences/occ-fa97469862136add.md|jquery.html[xfo]]]

