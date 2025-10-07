---
aliases:
  - "XCTO-0021"
cweId: "693"
cweUri: "https://cwe.mitre.org/data/definitions/693.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10021"
name: "X-Content-Type-Options Header Missing"
occurrenceCount: "225"
pluginId: "10021"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "225"
wascId: "15"
---

# X-Content-Type-Options Header Missing (Plugin 10021)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XContentTypeOptionsScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XContentTypeOptionsScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10021/

### How it detects

Passive; checks headers: X-Content-Type-Options; sets evidence

Signals:
- header:X-Content-Type-Options

## Remediation

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### References
- https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)
- https://owasp.org/www-community/Security_Headers
- https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941%28v=vs.85%29

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef75eb3eaa2dcd27.md|Issue fin-ef75eb3eaa2dcd27]]
#### Observations
- [[occurrences/occ-717cc6a7f671dcc0.md|public-firing-range.appspot.com/[xcto]]]

### GET https://public-firing-range.appspot.com/address/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f41aa280e74b7a5a.md|Issue fin-f41aa280e74b7a5a]]
#### Observations
- [[occurrences/occ-82b4485d0f6ef867.md|address[xcto]]]

### GET https://public-firing-range.appspot.com/address/URL/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8542b50977f8815a.md|Issue fin-8542b50977f8815a]]
#### Observations
- [[occurrences/occ-32175c7a228840cb.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/address/URLUnencoded/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-01ac96a345a3cf4a.md|Issue fin-01ac96a345a3cf4a]]
#### Observations
- [[occurrences/occ-652561abb64d3a6f.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/address/baseURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5370818cc4fda17d.md|Issue fin-5370818cc4fda17d]]
#### Observations
- [[occurrences/occ-f86fbadcb2c255eb.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/address/documentURI/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-efe5d93665865929.md|Issue fin-efe5d93665865929]]
#### Observations
- [[occurrences/occ-095f616fc6a37eb4.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/address/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f76e74a71d0944af.md|Issue fin-f76e74a71d0944af]]
#### Observations
- [[occurrences/occ-8c5ec3c992f15575.md|address/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-56b2ad256ce6fe36.md|Issue fin-56b2ad256ce6fe36]]
#### Observations
- [[occurrences/occ-8a06e0edef96a734.md|assign[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-afafd465300ff6e4.md|Issue fin-afafd465300ff6e4]]
#### Observations
- [[occurrences/occ-5fc9b5b5b0155fca.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f9115d9eca25272a.md|Issue fin-f9115d9eca25272a]]
#### Observations
- [[occurrences/occ-f67fbfb9d9a67ad8.md|documentwriteln[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5903f318e45f8dbb.md|Issue fin-5903f318e45f8dbb]]
#### Observations
- [[occurrences/occ-932ce1b7a1b646b5.md|eval[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-055ea32104a61c7d.md|Issue fin-055ea32104a61c7d]]
#### Observations
- [[occurrences/occ-5ffbfbc7808f86c6.md|formaction[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/function  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a8253eb389c4d2e0.md|Issue fin-a8253eb389c4d2e0]]
#### Observations
- [[occurrences/occ-8c1afa98864bdf69.md|function[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/inlineevent  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-55d272c738563d14.md|Issue fin-55d272c738563d14]]
#### Observations
- [[occurrences/occ-01f6033fabce673d.md|inlineevent[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-31bb57c9664a9b93.md|Issue fin-31bb57c9664a9b93]]
#### Observations
- [[occurrences/occ-bfdcc60d72bc461d.md|innerHtml[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/jshref  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7a116cfe5a54fe89.md|Issue fin-7a116cfe5a54fe89]]
#### Observations
- [[occurrences/occ-c34586b22f0b70c2.md|jshref[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickAddEventListener  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6191ab9135df0315.md|Issue fin-6191ab9135df0315]]
#### Observations
- [[occurrences/occ-db49b3f5ce6dd52c.md|onclickAddEventListener[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/onclickSetAttribute  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d3c38323ea75ecbb.md|Issue fin-d3c38323ea75ecbb]]
#### Observations
- [[occurrences/occ-5fbbd11ff3bd870c.md|onclickSetAttribute[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8bf09bee72d8d1ff.md|Issue fin-8bf09bee72d8d1ff]]
#### Observations
- [[occurrences/occ-81e0cfd82071048d.md|rangeCreateContextualFragment[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7dd35513b64b192b.md|Issue fin-7dd35513b64b192b]]
#### Observations
- [[occurrences/occ-49bb38479b9e0513.md|replace[xcto]]]

### GET https://public-firing-range.appspot.com/address/location.hash/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8ea53cab7285d961.md|Issue fin-8ea53cab7285d961]]
#### Observations
- [[occurrences/occ-58067518dce564ac.md|setTimeout[xcto]]]

### GET https://public-firing-range.appspot.com/address/location/assign  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-95b8a70af357626d.md|Issue fin-95b8a70af357626d]]
#### Observations
- [[occurrences/occ-a69795a327d365ec.md|assign[xcto]]]

### GET https://public-firing-range.appspot.com/address/location/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-93d9e2164ff40818.md|Issue fin-93d9e2164ff40818]]
#### Observations
- [[occurrences/occ-b956bd4093375ff7.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/address/location/documentwriteln  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2c0771e611d39b63.md|Issue fin-2c0771e611d39b63]]
#### Observations
- [[occurrences/occ-a8be64ef91e61869.md|documentwriteln[xcto]]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cd988adec6e97c2c.md|Issue fin-cd988adec6e97c2c]]
#### Observations
- [[occurrences/occ-84b8baf787108617.md|eval[xcto]]]

### GET https://public-firing-range.appspot.com/address/location/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-77eaf559b7fa3e55.md|Issue fin-77eaf559b7fa3e55]]
#### Observations
- [[occurrences/occ-4bc8e2ae38e719af.md|innerHtml[xcto]]]

### GET https://public-firing-range.appspot.com/address/location/rangeCreateContextualFragment  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7a0d674154414d19.md|Issue fin-7a0d674154414d19]]
#### Observations
- [[occurrences/occ-16c065f0f36004e0.md|rangeCreateContextualFragment[xcto]]]

### GET https://public-firing-range.appspot.com/address/location/replace  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bf02fd07f2c98786.md|Issue fin-bf02fd07f2c98786]]
#### Observations
- [[occurrences/occ-2091579d5332f9f6.md|replace[xcto]]]

### GET https://public-firing-range.appspot.com/address/location/setTimeout  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-adb1834d17f2f987.md|Issue fin-adb1834d17f2f987]]
#### Observations
- [[occurrences/occ-669be5016dcd17d8.md|setTimeout[xcto]]]

### GET https://public-firing-range.appspot.com/address/locationhref/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f2992d8e28a44d8a.md|Issue fin-f2992d8e28a44d8a]]
#### Observations
- [[occurrences/occ-7a5282e14b0d8465.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/address/locationpathname/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0091761ec8c5d85a.md|Issue fin-0091761ec8c5d85a]]
#### Observations
- [[occurrences/occ-7d7f2fae415737c9.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/address/locationsearch/documentwrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a4f05742c135636b.md|Issue fin-a4f05742c135636b]]
#### Observations
- [[occurrences/occ-21fecfb351bde2e3.md|documentwrite[xcto]]]

### GET https://public-firing-range.appspot.com/angular/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6925caa2b59f28d0.md|Issue fin-6925caa2b59f28d0]]
#### Observations
- [[occurrences/occ-c080846d25a7b419.md|angular[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de82aeb445376ac6.md|Issue fin-de82aeb445376ac6]]
#### Observations
- [[occurrences/occ-9b21ce3f1b0aad7e.md|1.1.5[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-37a9bc071e15eb31.md|Issue fin-37a9bc071e15eb31]]
#### Observations
- [[occurrences/occ-51a46d41719be36a.md|1.2.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9c633bef9bff3f5c.md|Issue fin-9c633bef9bff3f5c]]
#### Observations
- [[occurrences/occ-4dcc56415a295f10.md|1.2.18[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5b6a991b7185e5e1.md|Issue fin-5b6a991b7185e5e1]]
#### Observations
- [[occurrences/occ-44c32d2690dbd5c4.md|1.2.19[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-44d7fcd9393a6869.md|Issue fin-44d7fcd9393a6869]]
#### Observations
- [[occurrences/occ-693387179736f33a.md|1.2.24[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ff3d6ec2509e22bc.md|Issue fin-ff3d6ec2509e22bc]]
#### Observations
- [[occurrences/occ-69dfaf89fe4bbd80.md|1.4.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f82b35a65890f3db.md|Issue fin-f82b35a65890f3db]]
#### Observations
- [[occurrences/occ-adf84839e8003616.md|1.6.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c3f602aba75b7020.md|Issue fin-c3f602aba75b7020]]
#### Observations
- [[occurrences/occ-99528139954d7a25.md|1.4.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6f4c550e7d3f7a5d.md|Issue fin-6f4c550e7d3f7a5d]]
#### Observations
- [[occurrences/occ-6b180b44b7d97649.md|1.6.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c6e96a18fd58c27b.md|Issue fin-c6e96a18fd58c27b]]
#### Observations
- [[occurrences/occ-d83dec462e58dd57.md|1.4.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e8edc78fdfe1b364.md|Issue fin-e8edc78fdfe1b364]]
#### Observations
- [[occurrences/occ-8731a75b3932bc58.md|1.4.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ef4896295ece0505.md|Issue fin-ef4896295ece0505]]
#### Observations
- [[occurrences/occ-2888489e8114be09.md|1.4.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e41c1ca9611ee397.md|Issue fin-e41c1ca9611ee397]]
#### Observations
- [[occurrences/occ-40460c8cca385618.md|1.4.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-091bb2dd1c28c206.md|Issue fin-091bb2dd1c28c206]]
#### Observations
- [[occurrences/occ-0b7d916286712089.md|1.4.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-896fe6592c2be1c6.md|Issue fin-896fe6592c2be1c6]]
#### Observations
- [[occurrences/occ-8506f5eba7aa5ff6.md|1.4.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6d4b631605c7a2b8.md|Issue fin-6d4b631605c7a2b8]]
#### Observations
- [[occurrences/occ-b0df79eab51c6274.md|1.6.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-745d1c905ff586e8.md|Issue fin-745d1c905ff586e8]]
#### Observations
- [[occurrences/occ-87b4765754aff365.md|1.6.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8c2c06a0e08ce399.md|Issue fin-8c2c06a0e08ce399]]
#### Observations
- [[occurrences/occ-bfa258f037b25eca.md|1.6.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1f7f8dbc0ee4c8a3.md|Issue fin-1f7f8dbc0ee4c8a3]]
#### Observations
- [[occurrences/occ-de89db92ddfe7de3.md|1.6.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc1fb0bacf11dfa3.md|Issue fin-fc1fb0bacf11dfa3]]
#### Observations
- [[occurrences/occ-da03dbb076140939.md|1.6.0[xcto]]]

### GET https://public-firing-range.appspot.com/angular/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db4e119f30e67894.md|Issue fin-db4e119f30e67894]]
#### Observations
- [[occurrences/occ-2e3e0e340e3103e0.md|angular/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-00343cfbd3907db1.md|Issue fin-00343cfbd3907db1]]
#### Observations
- [[occurrences/occ-2d7bb4ff200009c2.md|badscriptimport[xcto]]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-96d2eb1955866857.md|Issue fin-96d2eb1955866857]]
#### Observations
- [[occurrences/occ-38aa3911845952a8.md|badscriptimport/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/clickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c0b8d57555a0d178.md|Issue fin-c0b8d57555a0d178]]
#### Observations
- [[occurrences/occ-4e7238a259d889fb.md|clickjacking[xcto]]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_csp_no_frame_ancestors  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bae9968d7440a446.md|Issue fin-bae9968d7440a446]]
#### Observations
- [[occurrences/occ-2a48e1facf83b3c7.md|clickjacking_csp_no…rame_ancestors[xcto]]]

### GET https://public-firing-range.appspot.com/clickjacking/clickjacking_xfo_allowall  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5b6a60c6a0be9218.md|Issue fin-5b6a60c6a0be9218]]
#### Observations
- [[occurrences/occ-807513498099f7b6.md|clickjacking_xfo_allowall[xcto]]]

### GET https://public-firing-range.appspot.com/clickjacking/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e3ce8be1dd10a081.md|Issue fin-e3ce8be1dd10a081]]
#### Observations
- [[occurrences/occ-d99c470ce66fb6e7.md|clickjacking/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/cors/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-247047df32104466.md|Issue fin-247047df32104466]]
#### Observations
- [[occurrences/occ-983405ceb344fb47.md|cors[xcto]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowInsecureScheme  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-30ea9283489e0c54.md|Issue fin-30ea9283489e0c54]]
#### Observations
- [[occurrences/occ-d5620ab3fee1e3d9.md|allowInsecureScheme[xcto]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aca6a73d4bf4280d.md|Issue fin-aca6a73d4bf4280d]]
#### Observations
- [[occurrences/occ-7d43fd1c6a29b376.md|allowNullOrigin[xcto]]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1b973e72dc72e074.md|Issue fin-1b973e72dc72e074]]
#### Observations
- [[occurrences/occ-c72a8854925ffcf8.md|allowNullOrigin[xcto]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0ae870524294560b.md|Issue fin-0ae870524294560b]]
#### Observations
- [[occurrences/occ-19d4fbd634f455ca.md|allowOriginEndsWith[xcto]]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a158e01a7b3b1f7d.md|Issue fin-a158e01a7b3b1f7d]]
#### Observations
- [[occurrences/occ-310c8a7fd3c8f55a.md|allowOriginEndsWith[xcto]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginProtocolDowngrade  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0e930c7dbb9f601a.md|Issue fin-0e930c7dbb9f601a]]
#### Observations
- [[occurrences/occ-213c1aa55b903231.md|allowOriginProtocolDowngrade[xcto]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginRegexDot  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7ae9943a32446641.md|Issue fin-7ae9943a32446641]]
#### Observations
- [[occurrences/occ-d80b0a0cb2713c7a.md|allowOriginRegexDot[xcto]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d868c326a655a9cc.md|Issue fin-d868c326a655a9cc]]
#### Observations
- [[occurrences/occ-cda54b204f9f7122.md|allowOriginStartsWith[xcto]]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-87fd2710dc231b80.md|Issue fin-87fd2710dc231b80]]
#### Observations
- [[occurrences/occ-b1e0f36ad7c7a32a.md|allowOriginStartsWith[xcto]]]

### GET https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6a20a894a9b6d7e3.md|Issue fin-6a20a894a9b6d7e3]]
#### Observations
- [[occurrences/occ-c247b05f87f93329.md|dynamicAllowOrigin[xcto]]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-286bb1924dc8f527.md|Issue fin-286bb1924dc8f527]]
#### Observations
- [[occurrences/occ-b137d7765d32c79b.md|dynamicAllowOrigin[xcto]]]

### GET https://public-firing-range.appspot.com/cors/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ba3fbebc8f422468.md|Issue fin-ba3fbebc8f422468]]
#### Observations
- [[occurrences/occ-d1a9ab7ffe477676.md|cors/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/dom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2bae46cb82fc6360.md|Issue fin-2bae46cb82fc6360]]
#### Observations
- [[occurrences/occ-679189071b70ce10.md|dom[xcto]]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d532e77214461330.md|Issue fin-d532e77214461330]]
#### Observations
- [[occurrences/occ-52aba2db86bff6b3.md|dompropagation[xcto]]]

### GET https://public-firing-range.appspot.com/dom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8d34538b6d73127a.md|Issue fin-8d34538b6d73127a]]
#### Observations
- [[occurrences/occ-0c586c88e50ef8f1.md|dom/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/dom/javascripturi.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fdac32d4ecdf0075.md|Issue fin-fdac32d4ecdf0075]]
#### Observations
- [[occurrences/occ-c07e8793b18f1dd3.md|javascripturi.html[xcto]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b107c36d3117fdaf.md|Issue fin-b107c36d3117fdaf]]
#### Observations
- [[occurrences/occ-3ad19759513a00d2.md|complexMessageDocumentWriteEval[xcto]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/documentWrite  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-369bb156aecd9f4e.md|Issue fin-369bb156aecd9f4e]]
#### Observations
- [[occurrences/occ-1664b89f2c46b72e.md|documentWrite[xcto]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c77a5e624eac365c.md|Issue fin-c77a5e624eac365c]]
#### Observations
- [[occurrences/occ-8dc5182412d8de6f.md|eval[xcto]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d35f47174df85b5f.md|Issue fin-d35f47174df85b5f]]
#### Observations
- [[occurrences/occ-661f27b8502d7e60.md|improperOriginValid…ringComparison[xcto]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2e8da498b16f28a8.md|Issue fin-2e8da498b16f28a8]]
#### Observations
- [[occurrences/occ-cb30ea64575a409c.md|improperOriginValidationWithRegExp[xcto]]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/innerHtml  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3ce4023c40578061.md|Issue fin-3ce4023c40578061]]
#### Observations
- [[occurrences/occ-974652665234bb38.md|innerHtml[xcto]]]

### GET https://public-firing-range.appspot.com/escape/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-108ad6b9c5353c49.md|Issue fin-108ad6b9c5353c49]]
#### Observations
- [[occurrences/occ-47e3f7062caa47ec.md|escape[xcto]]]

### GET https://public-firing-range.appspot.com/escape/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ea462c838e2eca7b.md|Issue fin-ea462c838e2eca7b]]
#### Observations
- [[occurrences/occ-38da9b9eadbc0124.md|escape/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc92086d9a7b150d.md|Issue fin-fc92086d9a7b150d]]
#### Observations
- [[occurrences/occ-5d791be9550f6064.md|encodeURIComponent[xcto]]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1ab1202d00819ba9.md|Issue fin-1ab1202d00819ba9]]
#### Observations
- [[occurrences/occ-bb44ef27664a956f.md|escape[xcto]]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-339df6f9af6e365b.md|Issue fin-339df6f9af6e365b]]
#### Observations
- [[occurrences/occ-9ca3cd24ab8e88ba.md|html_escape[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-10c23060e72d6b57.md|Issue fin-10c23060e72d6b57]]
#### Observations
- [[occurrences/occ-89846e09cbd58b36.md|attribute_name[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-132d12fc2000a67e.md|Issue fin-132d12fc2000a67e]]
#### Observations
- [[occurrences/occ-823ec3087e385593.md|attribute_quoted[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-afb4bbc6a0189bcb.md|Issue fin-afb4bbc6a0189bcb]]
#### Observations
- [[occurrences/occ-c9086e473c788779.md|attribute_script[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-57e6d2a370c83d70.md|Issue fin-57e6d2a370c83d70]]
#### Observations
- [[occurrences/occ-33a3100b37328062.md|attribute_singlequoted[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6db2222b825c6f6d.md|Issue fin-6db2222b825c6f6d]]
#### Observations
- [[occurrences/occ-a592201e52a9fcb4.md|attribute_unquoted[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cb1d19a59c807f4f.md|Issue fin-cb1d19a59c807f4f]]
#### Observations
- [[occurrences/occ-21a925c83ed4f92f.md|body[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5c4f554b94dd4bf5.md|Issue fin-5c4f554b94dd4bf5]]
#### Observations
- [[occurrences/occ-b958d6b5d30286e5.md|body_comment[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-42b60cda6b6289dc.md|Issue fin-42b60cda6b6289dc]]
#### Observations
- [[occurrences/occ-90566d1972aada09.md|css_import[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-70b8b32abe998d99.md|Issue fin-70b8b32abe998d99]]
#### Observations
- [[occurrences/occ-587c0c266304474e.md|css_style[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fef7d530d88f3819.md|Issue fin-fef7d530d88f3819]]
#### Observations
- [[occurrences/occ-5ec9916cc3376419.md|css_style_font_value[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-957331f9e0437e62.md|Issue fin-957331f9e0437e62]]
#### Observations
- [[occurrences/occ-e3436f1cbfd26296.md|css_style_value[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f2f1ea876ad1d1d0.md|Issue fin-f2f1ea876ad1d1d0]]
#### Observations
- [[occurrences/occ-be6072cb3d81a47d.md|head[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-87b4b41ee1c31a2d.md|Issue fin-87b4b41ee1c31a2d]]
#### Observations
- [[occurrences/occ-a4f5f01b3c7c4c68.md|js_assignment[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f87fbf5446b3c3d.md|Issue fin-7f87fbf5446b3c3d]]
#### Observations
- [[occurrences/occ-9621a72cfb1fcbc8.md|js_comment[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dfbfed82fd2d67e8.md|Issue fin-dfbfed82fd2d67e8]]
#### Observations
- [[occurrences/occ-ba05713828422c14.md|js_eval[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-98d2f5e88c14c80b.md|Issue fin-98d2f5e88c14c80b]]
#### Observations
- [[occurrences/occ-af891c9c2cfdfa0e.md|js_quoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cc74e90c7c116191.md|Issue fin-cc74e90c7c116191]]
#### Observations
- [[occurrences/occ-478d36f86b2c9ec2.md|js_singlequoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8b67069e4fdb0b5a.md|Issue fin-8b67069e4fdb0b5a]]
#### Observations
- [[occurrences/occ-80807c4bcc8fe499.md|js_slashquoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-776070b760413d75.md|Issue fin-776070b760413d75]]
#### Observations
- [[occurrences/occ-8d015ee9c8cfdd1c.md|tagname[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cd87388c67873964.md|Issue fin-cd87388c67873964]]
#### Observations
- [[occurrences/occ-89a929276fda0611.md|textarea[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a3f43fad0c72313d.md|Issue fin-a3f43fad0c72313d]]
#### Observations
- [[occurrences/occ-af9632c5be94a898.md|attribute_name[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d76a4d28674887d7.md|Issue fin-d76a4d28674887d7]]
#### Observations
- [[occurrences/occ-ce3f311ae8170683.md|attribute_quoted[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-939318d5e7b3eeb0.md|Issue fin-939318d5e7b3eeb0]]
#### Observations
- [[occurrences/occ-f239ad9cc873fb58.md|attribute_script[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3ca4fdf08e480981.md|Issue fin-3ca4fdf08e480981]]
#### Observations
- [[occurrences/occ-e4d1441e14dd8f76.md|attribute_singlequoted[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-311345e1b8951f01.md|Issue fin-311345e1b8951f01]]
#### Observations
- [[occurrences/occ-aba1f387395948af.md|attribute_unquoted[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d3546989e31af369.md|Issue fin-d3546989e31af369]]
#### Observations
- [[occurrences/occ-09b65303939a7f0e.md|body[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-58f1edb3d2baf4d7.md|Issue fin-58f1edb3d2baf4d7]]
#### Observations
- [[occurrences/occ-c893ab3be9009b2d.md|body_comment[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fef80c8ed8787436.md|Issue fin-fef80c8ed8787436]]
#### Observations
- [[occurrences/occ-d2e0ef818ebcfcda.md|css_import[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8a2c292a63fb7e6e.md|Issue fin-8a2c292a63fb7e6e]]
#### Observations
- [[occurrences/occ-71423b8bc80adb6e.md|css_style[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c4f85cf6d11b0e6e.md|Issue fin-c4f85cf6d11b0e6e]]
#### Observations
- [[occurrences/occ-480e52a55d76e0e8.md|css_style_font_value[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/css_style_value?q=a&escape=HTML_ESCAPE  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-48f78461742ba672.md|Issue fin-48f78461742ba672]]
#### Observations
- [[occurrences/occ-66f1da6f82c76e72.md|css_style_value[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-99f8151fb7115e39.md|Issue fin-99f8151fb7115e39]]
#### Observations
- [[occurrences/occ-29c59483f3d3b8b5.md|head[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c33d4505d5012e39.md|Issue fin-c33d4505d5012e39]]
#### Observations
- [[occurrences/occ-9ef0339d36d98807.md|js_assignment[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9ba9e23bb3ef9e60.md|Issue fin-9ba9e23bb3ef9e60]]
#### Observations
- [[occurrences/occ-e567f7110ff48a79.md|js_comment[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4ec0257e93663463.md|Issue fin-4ec0257e93663463]]
#### Observations
- [[occurrences/occ-34c1c33429c4873e.md|js_eval[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cf97734bf00d33b1.md|Issue fin-cf97734bf00d33b1]]
#### Observations
- [[occurrences/occ-f0fc24a8e73500c1.md|js_quoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d0e638fb87716306.md|Issue fin-d0e638fb87716306]]
#### Observations
- [[occurrences/occ-119f2bdf44e54907.md|js_singlequoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-28eb47c6aad8b014.md|Issue fin-28eb47c6aad8b014]]
#### Observations
- [[occurrences/occ-e2fb686c3c1a6e9a.md|js_slashquoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bf28c512bedaca63.md|Issue fin-bf28c512bedaca63]]
#### Observations
- [[occurrences/occ-aa09bf234344e86a.md|tagname[xcto]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f9a8dbb12086600c.md|Issue fin-f9a8dbb12086600c]]
#### Observations
- [[occurrences/occ-c960fba57b08ccb9.md|textarea[xcto]]]

### GET https://public-firing-range.appspot.com/flashinjection/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-db1be0471460d543.md|Issue fin-db1be0471460d543]]
#### Observations
- [[occurrences/occ-f257c06f1c39b6b9.md|flashinjection[xcto]]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackIsEchoedBack?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-744ad9f8bd796fbf.md|Issue fin-744ad9f8bd796fbf]]
#### Observations
- [[occurrences/occ-1e92dff231d61097.md|callbackIsEchoedBack[xcto]]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackParameterDoesNothing?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d36e3745cc975283.md|Issue fin-d36e3745cc975283]]
#### Observations
- [[occurrences/occ-69d3656c130fd422.md|callbackParameterDoesNothing[xcto]]]

### GET https://public-firing-range.appspot.com/flashinjection/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b6cca7cbf972a80d.md|Issue fin-b6cca7cbf972a80d]]
#### Observations
- [[occurrences/occ-15fbc8320ead1e63.md|flashinjection/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-40c0e77c007cb313.md|Issue fin-40c0e77c007cb313]]
#### Observations
- [[occurrences/occ-aa0b6c85127bc838.md|insecurethirdpartyscripts[xcto]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-59ad6269a20857a2.md|Issue fin-59ad6269a20857a2]]
#### Observations
- [[occurrences/occ-6194067ffe01d3e0.md|insecurethirdpartys…pts/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d13d28bc199f8ca8.md|Issue fin-d13d28bc199f8ca8]]
#### Observations
- [[occurrences/occ-9d70b0588b353b5d.md|third_party_scripts…integrity.html[xcto]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3b38599cd5470570.md|Issue fin-3b38599cd5470570]]
#### Observations
- [[occurrences/occ-cabe6552de8e6899.md|third_party_scripts…lly_added.html[xcto]]]

### GET https://public-firing-range.appspot.com/leakedcookie/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7f8a5e08aac769c8.md|Issue fin-7f8a5e08aac769c8]]
#### Observations
- [[occurrences/occ-9118430dbbf9bb7f.md|leakedcookie[xcto]]]

### GET https://public-firing-range.appspot.com/leakedcookie/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9e58dee830248c12.md|Issue fin-9e58dee830248c12]]
#### Observations
- [[occurrences/occ-1cbc8349c06e33e2.md|leakedcookie/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4cb613dec40668e6.md|Issue fin-4cb613dec40668e6]]
#### Observations
- [[occurrences/occ-20c7baf105a5f014.md|leakedcookie[xcto]]]

### GET https://public-firing-range.appspot.com/leakedcookie/leakedinresource  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f32380932ec2bfc6.md|Issue fin-f32380932ec2bfc6]]
#### Observations
- [[occurrences/occ-451d8c89ad892b09.md|leakedinresource[xcto]]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fb1938b0e7fb1440.md|Issue fin-fb1938b0e7fb1440]]
#### Observations
- [[occurrences/occ-4a86b30d98663b95.md|mixedcontent[xcto]]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f83d09b266308e59.md|Issue fin-f83d09b266308e59]]
#### Observations
- [[occurrences/occ-122022e6a46ac09e.md|mixedcontent/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/redirect/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0dffe5a1dc80ecfa.md|Issue fin-0dffe5a1dc80ecfa]]
#### Observations
- [[occurrences/occ-9f9201f8c470a557.md|redirect[xcto]]]

### GET https://public-firing-range.appspot.com/redirect/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b7ea6414dd264114.md|Issue fin-b7ea6414dd264114]]
#### Observations
- [[occurrences/occ-48b35619f8436c77.md|redirect/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/redirect/meta?q=/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-64406bf496390c05.md|Issue fin-64406bf496390c05]]
#### Observations
- [[occurrences/occ-0759d5055306f91b.md|meta[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a96e41bae204ad8b.md|Issue fin-a96e41bae204ad8b]]
#### Observations
- [[occurrences/occ-cebe4ff76a5ecf9d.md|reflected[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b71811347b1f5749.md|Issue fin-b71811347b1f5749]]
#### Observations
- [[occurrences/occ-7e47c6c7b7ed088c.md|json[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/contentsniffing/plaintext?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc9bbcf3d0a6b09b.md|Issue fin-fc9bbcf3d0a6b09b]]
#### Observations
- [[occurrences/occ-eb209ee7de2b6a1f.md|plaintext[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_quoted/DOUBLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-537de52b93eaf60d.md|Issue fin-537de52b93eaf60d]]
#### Observations
- [[occurrences/occ-d222712d8ff12382.md|DOUBLE_QUOTED_ATTRIBUTE[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_singlequoted/SINGLE_QUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d9214b9246cb5986.md|Issue fin-d9214b9246cb5986]]
#### Observations
- [[occurrences/occ-b7ffbd73fd5ef5e1.md|SINGLE_QUOTED_ATTRIBUTE[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/escapedparameter/js_eventhandler_unquoted/UNQUOTED_ATTRIBUTE?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cb00e86b4d449512.md|Issue fin-cb00e86b4d449512]]
#### Observations
- [[occurrences/occ-6d882eafbde88c53.md|UNQUOTED_ATTRIBUTE[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/attribute_unquoted/DoubleQuoteSinglequote?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-02bf42e2b83c1cb7.md|Issue fin-02bf42e2b83c1cb7]]
#### Observations
- [[occurrences/occ-c524a840495b064f.md|DoubleQuoteSinglequote[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/filteredcharsets/body/SpaceDoubleQuoteSlashEquals?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-455b12cd39d9366a.md|Issue fin-455b12cd39d9366a]]
#### Observations
- [[occurrences/occ-004144212e378c8a.md|SpaceDoubleQuoteSlashEquals[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9f81a006b4e16ee8.md|Issue fin-9f81a006b4e16ee8]]
#### Observations
- [[occurrences/occ-31889e37c916599e.md|reflected/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/jsoncallback  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-91e8702240ef78af.md|Issue fin-91e8702240ef78af]]
#### Observations
- [[occurrences/occ-7d04f4c2c46749b9.md|jsoncallback[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_name?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f767d09d3d4c15bf.md|Issue fin-f767d09d3d4c15bf]]
#### Observations
- [[occurrences/occ-2b067493f1af999d.md|attribute_name[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dc5ba829e570a926.md|Issue fin-dc5ba829e570a926]]
#### Observations
- [[occurrences/occ-e0b3117bfa11e441.md|attribute_quoted[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dfc0956420fa4e33.md|Issue fin-dfc0956420fa4e33]]
#### Observations
- [[occurrences/occ-aa848fba7513c1df.md|attribute_script[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_singlequoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4eb708d6d00495e9.md|Issue fin-4eb708d6d00495e9]]
#### Observations
- [[occurrences/occ-948a1313dba3ffbd.md|attribute_singlequoted[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9faa9b0745b0760c.md|Issue fin-9faa9b0745b0760c]]
#### Observations
- [[occurrences/occ-c2b948ea255623e6.md|attribute_unquoted[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-73040167fb991d68.md|Issue fin-73040167fb991d68]]
#### Observations
- [[occurrences/occ-6c806c05f5931456.md|body[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/body_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7b2e72f5ffc749d9.md|Issue fin-7b2e72f5ffc749d9]]
#### Observations
- [[occurrences/occ-3c3b503a1fe38fee.md|body_comment[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9784834cc12b50e7.md|Issue fin-9784834cc12b50e7]]
#### Observations
- [[occurrences/occ-c56082509a7491ab.md|css_style[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_font_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0bdc5af21b6efe74.md|Issue fin-0bdc5af21b6efe74]]
#### Observations
- [[occurrences/occ-8f52bd4f826e9254.md|css_style_font_value[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/css_style_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-25e2756fcc70c1d7.md|Issue fin-25e2756fcc70c1d7]]
#### Observations
- [[occurrences/occ-aec0e8edbfecadfc.md|css_style_value[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/form  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2f2cd473ab5d646e.md|Issue fin-2f2cd473ab5d646e]]
#### Observations
- [[occurrences/occ-5d1702b722f3c534.md|form[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/head?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-031ae99f011257b5.md|Issue fin-031ae99f011257b5]]
#### Observations
- [[occurrences/occ-09d6157872d02fd4.md|head[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3e245c53d6cea0ca.md|Issue fin-3e245c53d6cea0ca]]
#### Observations
- [[occurrences/occ-32611ca50946c13b.md|iframe_attribute_value[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/iframe_srcdoc?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b424e5a906ce9161.md|Issue fin-b424e5a906ce9161]]
#### Observations
- [[occurrences/occ-a54ba7dc62f4e16a.md|iframe_srcdoc[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_assignment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-49dad466789dc036.md|Issue fin-49dad466789dc036]]
#### Observations
- [[occurrences/occ-7f0791f8b3d8a766.md|js_assignment[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_comment?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4559276ae6ebc475.md|Issue fin-4559276ae6ebc475]]
#### Observations
- [[occurrences/occ-22be711c3631c7a7.md|js_comment[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-26ff19389a8c3ce6.md|Issue fin-26ff19389a8c3ce6]]
#### Observations
- [[occurrences/occ-4d42a8c6f6162267.md|js_eval[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ab4c894d36ea4512.md|Issue fin-ab4c894d36ea4512]]
#### Observations
- [[occurrences/occ-3adaa932ee00c916.md|js_quoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-725ea1d4006d90a9.md|Issue fin-725ea1d4006d90a9]]
#### Observations
- [[occurrences/occ-d93b86eeda2308c6.md|js_singlequoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_slashquoted_string?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1d123eb84902395c.md|Issue fin-1d123eb84902395c]]
#### Observations
- [[occurrences/occ-1defb53712f44e78.md|js_slashquoted_string[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/json?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eaf0740c4c0899cd.md|Issue fin-eaf0740c4c0899cd]]
#### Observations
- [[occurrences/occ-a7f440c292c2c926.md|json[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/noscript?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-179dbc108ac6ca67.md|Issue fin-179dbc108ac6ca67]]
#### Observations
- [[occurrences/occ-deb92ad0548ad39c.md|noscript[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/style_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f18e95de46dda5b9.md|Issue fin-f18e95de46dda5b9]]
#### Observations
- [[occurrences/occ-3051536a62b7d76f.md|style_attribute_value[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/tagname?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6d65e95ef73d15b6.md|Issue fin-6d65e95ef73d15b6]]
#### Observations
- [[occurrences/occ-d41c50ae3df3fcad.md|tagname[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-228b7f28ccc67b47.md|Issue fin-228b7f28ccc67b47]]
#### Observations
- [[occurrences/occ-9498b57c6e965a19.md|textarea[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/textarea_attribute_value?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-346286da6f0face9.md|Issue fin-346286da6f0face9]]
#### Observations
- [[occurrences/occ-d65e193b4c1c2bd2.md|textarea_attribute_value[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/title?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fb44a05625bf482a.md|Issue fin-fb44a05625bf482a]]
#### Observations
- [[occurrences/occ-51967df4a4c4aef3.md|title[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/url/css_import?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-08d2c5c002a87317.md|Issue fin-08d2c5c002a87317]]
#### Observations
- [[occurrences/occ-a2a30f674c993006.md|css_import[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/url/href?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f32cf16f7aef9390.md|Issue fin-f32cf16f7aef9390]]
#### Observations
- [[occurrences/occ-fce6956f39bbb113.md|href[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/url/object_data?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cc4ecc732edecaaf.md|Issue fin-cc4ecc732edecaaf]]
#### Observations
- [[occurrences/occ-8afff48243ab8a00.md|object_data[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/url/object_param?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4b6a1cc80e2a476d.md|Issue fin-4b6a1cc80e2a476d]]
#### Observations
- [[occurrences/occ-58862baa5f3562bc.md|object_param[xcto]]]

### GET https://public-firing-range.appspot.com/reflected/url/script_src?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3880965298036283.md|Issue fin-3880965298036283]]
#### Observations
- [[occurrences/occ-15936bef69b2ff98.md|script_src[xcto]]]

### GET https://public-firing-range.appspot.com/remoteinclude/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-84a811139d0832d9.md|Issue fin-84a811139d0832d9]]
#### Observations
- [[occurrences/occ-50ca5922e91b3891.md|remoteinclude[xcto]]]

### GET https://public-firing-range.appspot.com/remoteinclude/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-65647c980314b679.md|Issue fin-65647c980314b679]]
#### Observations
- [[occurrences/occ-1d38b87a01a66242.md|remoteinclude/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f45b2221ceedc442.md|Issue fin-f45b2221ceedc442]]
#### Observations
- [[occurrences/occ-a1f246bf67545383.md|object_hash.html[xcto]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object/application_x-shockwave-flash?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-39b36881ee9d1cf1.md|Issue fin-39b36881ee9d1cf1]]
#### Observations
- [[occurrences/occ-c139b21e92634058.md|application_x-shockwave-flash[xcto]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/object_raw?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-cac79d245dce2296.md|Issue fin-cac79d245dce2296]]
#### Observations
- [[occurrences/occ-5e647710e12e0324.md|object_raw[xcto]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f3ab2531bce023c4.md|Issue fin-f3ab2531bce023c4]]
#### Observations
- [[occurrences/occ-26ed03ff56ce36cd.md|script[xcto]]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-39d32e0bb8762550.md|Issue fin-39d32e0bb8762550]]
#### Observations
- [[occurrences/occ-f6f6f99d5516030a.md|script_hash.html[xcto]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d6d979e852b3b07e.md|Issue fin-d6d979e852b3b07e]]
#### Observations
- [[occurrences/occ-56cf936d942c1d46.md|reverseclickjacking[xcto]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/InCallback/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-946f8b365db91369.md|Issue fin-946f8b365db91369]]
#### Observations
- [[occurrences/occ-196a450a61130d63.md|InCallback[xcto]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInFragment/OtherParameter/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f81402b6fa13dafc.md|Issue fin-f81402b6fa13dafc]]
#### Observations
- [[occurrences/occ-700e278a42a1c8ec.md|OtherParameter[xcto]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/InCallback/?q=urc_button.click  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-91c10595c0300f22.md|Issue fin-91c10595c0300f22]]
#### Observations
- [[occurrences/occ-72ea68ace93c6178.md|InCallback[xcto]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/singlepage/ParameterInQuery/OtherParameter/?q=%26callback%3Durc_button.click%23  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-825e133528b4e2b5.md|Issue fin-825e133528b4e2b5]]
#### Observations
- [[occurrences/occ-33083b28a7266bc6.md|OtherParameter[xcto]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dd9b0732a1ed7797.md|Issue fin-dd9b0732a1ed7797]]
#### Observations
- [[occurrences/occ-f52354f2aa4201ae.md|stricttransportsecurity[xcto]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_includesubdomains_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fd6a467e44549f27.md|Issue fin-fd6a467e44549f27]]
#### Observations
- [[occurrences/occ-87b7ec41daebd894.md|hsts_includesubdomains_missing[xcto]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-40fe9850f23b1815.md|Issue fin-40fe9850f23b1815]]
#### Observations
- [[occurrences/occ-3df6d173d0c3d645.md|hsts_max_age_missing[xcto]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_max_age_too_low  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-936de3297d5226e7.md|Issue fin-936de3297d5226e7]]
#### Observations
- [[occurrences/occ-153aee5fe799b48f.md|hsts_max_age_too_low[xcto]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-61497356b53e4b4d.md|Issue fin-61497356b53e4b4d]]
#### Observations
- [[occurrences/occ-665ccea83ec664c8.md|hsts_missing[xcto]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/hsts_preload_missing  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d04c77aac004fe7b.md|Issue fin-d04c77aac004fe7b]]
#### Observations
- [[occurrences/occ-25608398134d8d43.md|hsts_preload_missing[xcto]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dc684dcf8f5ea176.md|Issue fin-dc684dcf8f5ea176]]
#### Observations
- [[occurrences/occ-ac36f95e99359826.md|stricttransportsecurity/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/tags/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-15af76ec37a2cbdc.md|Issue fin-15af76ec37a2cbdc]]
#### Observations
- [[occurrences/occ-afc2e40da530c0f7.md|tags[xcto]]]

### GET https://public-firing-range.appspot.com/tags/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-67496d22965c73ef.md|Issue fin-67496d22965c73ef]]
#### Observations
- [[occurrences/occ-0b4a84a8cb93bce2.md|tags/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/tags/multiline?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2b4b7690f6ed959a.md|Issue fin-2b4b7690f6ed959a]]
#### Observations
- [[occurrences/occ-6c5adedc4af45374.md|multiline[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d2a4a5613e7d861b.md|Issue fin-d2a4a5613e7d861b]]
#### Observations
- [[occurrences/occ-550d3bdf754a5764.md|urldom[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5c7d576c929021bb.md|Issue fin-5c7d576c929021bb]]
#### Observations
- [[occurrences/occ-f74f2e97b1105359.md|urldom/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/jsonp?callback=foo  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-94b32970c7a2d37d.md|Issue fin-94b32970c7a2d37d]]
#### Observations
- [[occurrences/occ-6bc6fbff060e08ad.md|jsonp[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/jsonp?callback=foobar  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bdc20cca6fda2ad2.md|Issue fin-bdc20cca6fda2ad2]]
#### Observations
- [[occurrences/occ-0ebba24a7bf49bf8.md|jsonp[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_domain  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8c295b9bb3abbc8e.md|Issue fin-8c295b9bb3abbc8e]]
#### Observations
- [[occurrences/occ-ba5fb805f98c33f2.md|script.src.partial_domain[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/location/hash/script.src.partial_query  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6e008d8149011024.md|Issue fin-6e008d8149011024]]
#### Observations
- [[occurrences/occ-2fc79d3c0dddadd1.md|script.src.partial_query[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/area.href?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bdeb695dc4b27d6b.md|Issue fin-bdeb695dc4b27d6b]]
#### Observations
- [[occurrences/occ-17ef0c1811267fb6.md|area.href[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d3cb5ad62ebe6ed8.md|Issue fin-d3cb5ad62ebe6ed8]]
#### Observations
- [[occurrences/occ-fee2875a4624730b.md|button.formaction[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/button.formaction?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ee9192a42940388b.md|Issue fin-ee9192a42940388b]]
#### Observations
- [[occurrences/occ-2e10fceaf95946bc.md|button.formaction[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/frame.src?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-407a9838d418dfae.md|Issue fin-407a9838d418dfae]]
#### Observations
- [[occurrences/occ-d4bcc1ed61f5b46d.md|frame.src[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/location.assign?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-512e9c160b53e879.md|Issue fin-512e9c160b53e879]]
#### Observations
- [[occurrences/occ-a853d38b702ffdff.md|location.assign[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/location/search/svg.a?//example.org  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e159fcf7a7cd6d4b.md|Issue fin-e159fcf7a7cd6d4b]]
#### Observations
- [[occurrences/occ-ede644111c6dd8c8.md|svg.a[xcto]]]

### GET https://public-firing-range.appspot.com/urldom/script.js  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4cc7a03faf9f3790.md|Issue fin-4cc7a03faf9f3790]]
#### Observations
- [[occurrences/occ-05087f433f6f2a02.md|script.js[xcto]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ad8677b06a595915.md|Issue fin-ad8677b06a595915]]
#### Observations
- [[occurrences/occ-af45bfc9a38ddb9a.md|vulnerablelibraries[xcto]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec0b735a7faef8b2.md|Issue fin-ec0b735a7faef8b2]]
#### Observations
- [[occurrences/occ-e956ea3baa0e7b76.md|vulnerablelibraries/index.html[xcto]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6310f382a3d6baea.md|Issue fin-6310f382a3d6baea]]
#### Observations
- [[occurrences/occ-362eae8c0b1a8486.md|jquery.html[xcto]]]

