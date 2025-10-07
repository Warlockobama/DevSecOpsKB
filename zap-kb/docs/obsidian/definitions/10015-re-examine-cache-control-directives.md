---
aliases:
  - "RECCD-0015"
cweId: "525"
cweUri: "https://cwe.mitre.org/data/definitions/525.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10015"
name: "Re-examine Cache-control Directives"
occurrenceCount: "46"
pluginId: "10015"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "46"
wascId: "13"
---

# Re-examine Cache-control Directives (Plugin 10015)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CacheControlScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CacheControlScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10015/

### How it detects

Passive; checks headers: Cache-Control; sets evidence; threshold: low

_threshold: low_

Signals:
- header:Cache-Control

## Remediation

For secure content, ensure the cache-control HTTP header is set with "no-cache, no-store, must-revalidate". If an asset should be cached consider setting the directives "public, max-age, immutable".

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
- https://grayduck.mn/2021/09/13/cache-control-recommendations/
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control

## Issues

### GET https://public-firing-range.appspot.com/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2c7883f2fe944556.md|Issue fin-2c7883f2fe944556]]
#### Observations
- [[occurrences/occ-7a8dc675ad1e6f8e.md|public-firing-range.appspot.com/[cc]]]

### GET https://public-firing-range.appspot.com/address/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e738c463863fa4da.md|Issue fin-e738c463863fa4da]]
#### Observations
- [[occurrences/occ-762ada2f0ecdf12f.md|address[cc]]]

### GET https://public-firing-range.appspot.com/address/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-74f73de4933cf9a2.md|Issue fin-74f73de4933cf9a2]]
#### Observations
- [[occurrences/occ-8d5ddf67cb81d55e.md|address/index.html[cc]]]

### GET https://public-firing-range.appspot.com/angular/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2d3a9116efd3ad3b.md|Issue fin-2d3a9116efd3ad3b]]
#### Observations
- [[occurrences/occ-2810b9356be19407.md|angular[cc]]]

### GET https://public-firing-range.appspot.com/angular/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7fd9a420159e7c4e.md|Issue fin-7fd9a420159e7c4e]]
#### Observations
- [[occurrences/occ-31985d47967215cf.md|angular/index.html[cc]]]

### GET https://public-firing-range.appspot.com/badscriptimport/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-eadee9ecc6546118.md|Issue fin-eadee9ecc6546118]]
#### Observations
- [[occurrences/occ-9e5d35a6bdff1970.md|badscriptimport[cc]]]

### GET https://public-firing-range.appspot.com/badscriptimport/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-19e377b9e919ccd8.md|Issue fin-19e377b9e919ccd8]]
#### Observations
- [[occurrences/occ-4ac3fd5624308ef1.md|badscriptimport/index.html[cc]]]

### GET https://public-firing-range.appspot.com/clickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-14070fe3f88aa889.md|Issue fin-14070fe3f88aa889]]
#### Observations
- [[occurrences/occ-10d0ca2b8149280e.md|clickjacking[cc]]]

### GET https://public-firing-range.appspot.com/clickjacking/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-393d2868b0e3a464.md|Issue fin-393d2868b0e3a464]]
#### Observations
- [[occurrences/occ-b926722ec834d0ca.md|clickjacking/index.html[cc]]]

### GET https://public-firing-range.appspot.com/cors/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-fc6a691c7d7b61e3.md|Issue fin-fc6a691c7d7b61e3]]
#### Observations
- [[occurrences/occ-333dd052455fa912.md|cors[cc]]]

### GET https://public-firing-range.appspot.com/cors/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4a4a138b5d3aafd8.md|Issue fin-4a4a138b5d3aafd8]]
#### Observations
- [[occurrences/occ-0e4ead3425ec4d08.md|cors/index.html[cc]]]

### GET https://public-firing-range.appspot.com/dom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-86ebe6b64510e00b.md|Issue fin-86ebe6b64510e00b]]
#### Observations
- [[occurrences/occ-df2dcca634069497.md|dom[cc]]]

### GET https://public-firing-range.appspot.com/dom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec069b15be404d43.md|Issue fin-ec069b15be404d43]]
#### Observations
- [[occurrences/occ-293d0c96eb9eabd4.md|dom/index.html[cc]]]

### GET https://public-firing-range.appspot.com/dom/javascripturi.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-996237133ed97f50.md|Issue fin-996237133ed97f50]]
#### Observations
- [[occurrences/occ-90883a75126b8cb1.md|javascripturi.html[cc]]]

### GET https://public-firing-range.appspot.com/escape/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e6120c4f9f13c098.md|Issue fin-e6120c4f9f13c098]]
#### Observations
- [[occurrences/occ-18378928865f0a80.md|escape[cc]]]

### GET https://public-firing-range.appspot.com/escape/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-72a843051adc5c03.md|Issue fin-72a843051adc5c03]]
#### Observations
- [[occurrences/occ-5194dbdce1bd465d.md|escape/index.html[cc]]]

### GET https://public-firing-range.appspot.com/flashinjection/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7a8727054dc9babf.md|Issue fin-7a8727054dc9babf]]
#### Observations
- [[occurrences/occ-aa151f626576e95e.md|flashinjection[cc]]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackIsEchoedBack?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f11abb7ac5d5ab88.md|Issue fin-f11abb7ac5d5ab88]]
#### Observations
- [[occurrences/occ-5acc11c7ab3e2248.md|callbackIsEchoedBack[cc]]]

### GET https://public-firing-range.appspot.com/flashinjection/callbackParameterDoesNothing?callback=func  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-66a7ef58235b352d.md|Issue fin-66a7ef58235b352d]]
#### Observations
- [[occurrences/occ-e93e948d4de497a1.md|callbackParameterDoesNothing[cc]]]

### GET https://public-firing-range.appspot.com/flashinjection/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-776aa2c5e6af7bef.md|Issue fin-776aa2c5e6af7bef]]
#### Observations
- [[occurrences/occ-6a15956a1c02e64a.md|flashinjection/index.html[cc]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4ab1e7737b748220.md|Issue fin-4ab1e7737b748220]]
#### Observations
- [[occurrences/occ-3f77681e0a13a3ff.md|insecurethirdpartyscripts[cc]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7e7bfd2811432d80.md|Issue fin-7e7bfd2811432d80]]
#### Observations
- [[occurrences/occ-15bdf5e50a018c9c.md|insecurethirdpartyscripts/index.html[cc]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-e8df2c3ba2b038a3.md|Issue fin-e8df2c3ba2b038a3]]
#### Observations
- [[occurrences/occ-bd8d55463502979d.md|third_party_scripts…e_integrity.html[cc]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity_dynamically_added.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-49a1e39d81474871.md|Issue fin-49a1e39d81474871]]
#### Observations
- [[occurrences/occ-928c82c6a5730269.md|third_party_scripts…cally_added.html[cc]]]

### GET https://public-firing-range.appspot.com/leakedcookie/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dc7032b0704c6702.md|Issue fin-dc7032b0704c6702]]
#### Observations
- [[occurrences/occ-1fb0da05ea0b9801.md|leakedcookie[cc]]]

### GET https://public-firing-range.appspot.com/leakedcookie/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-466257cf34c9eb43.md|Issue fin-466257cf34c9eb43]]
#### Observations
- [[occurrences/occ-ff7675ef7b4e25b0.md|leakedcookie/index.html[cc]]]

### GET https://public-firing-range.appspot.com/mixedcontent/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-886fda46c6fd19ff.md|Issue fin-886fda46c6fd19ff]]
#### Observations
- [[occurrences/occ-26ddb7a6b788c4c1.md|mixedcontent[cc]]]

### GET https://public-firing-range.appspot.com/mixedcontent/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ec7c1c5d5de9b2a2.md|Issue fin-ec7c1c5d5de9b2a2]]
#### Observations
- [[occurrences/occ-89f5e78fe53c01f7.md|mixedcontent/index.html[cc]]]

### GET https://public-firing-range.appspot.com/redirect/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c62318216fd724aa.md|Issue fin-c62318216fd724aa]]
#### Observations
- [[occurrences/occ-df9a01eba47f72d8.md|redirect[cc]]]

### GET https://public-firing-range.appspot.com/redirect/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c70a73729e6093ae.md|Issue fin-c70a73729e6093ae]]
#### Observations
- [[occurrences/occ-24ea3bfae038ad28.md|redirect/index.html[cc]]]

### GET https://public-firing-range.appspot.com/reflected/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0cd2f5a9e89859bd.md|Issue fin-0cd2f5a9e89859bd]]
#### Observations
- [[occurrences/occ-56f8b339046adf35.md|reflected[cc]]]

### GET https://public-firing-range.appspot.com/reflected/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-53b74679d70ad6e0.md|Issue fin-53b74679d70ad6e0]]
#### Observations
- [[occurrences/occ-9def65b22639521d.md|reflected/index.html[cc]]]

### GET https://public-firing-range.appspot.com/remoteinclude/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-8f33fb004568d960.md|Issue fin-8f33fb004568d960]]
#### Observations
- [[occurrences/occ-fb39792e939577dd.md|remoteinclude[cc]]]

### GET https://public-firing-range.appspot.com/remoteinclude/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ebe89879254b2693.md|Issue fin-ebe89879254b2693]]
#### Observations
- [[occurrences/occ-20aeb6e963563f82.md|remoteinclude/index.html[cc]]]

### GET https://public-firing-range.appspot.com/remoteinclude/object_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5f856a6812113bca.md|Issue fin-5f856a6812113bca]]
#### Observations
- [[occurrences/occ-b8b5328d1652fec6.md|object_hash.html[cc]]]

### GET https://public-firing-range.appspot.com/remoteinclude/script_hash.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5008eba8241a8e11.md|Issue fin-5008eba8241a8e11]]
#### Observations
- [[occurrences/occ-d1908195f4d101c2.md|script_hash.html[cc]]]

### GET https://public-firing-range.appspot.com/reverseclickjacking/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-971bbc502aa06a92.md|Issue fin-971bbc502aa06a92]]
#### Observations
- [[occurrences/occ-435838e55e5d9130.md|reverseclickjacking[cc]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6f18290efb943763.md|Issue fin-6f18290efb943763]]
#### Observations
- [[occurrences/occ-37958a30a0cc6665.md|stricttransportsecurity[cc]]]

### GET https://public-firing-range.appspot.com/stricttransportsecurity/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ad7cd6aec4bcca7a.md|Issue fin-ad7cd6aec4bcca7a]]
#### Observations
- [[occurrences/occ-616dacff8d727b2d.md|stricttransportsecurity/index.html[cc]]]

### GET https://public-firing-range.appspot.com/tags/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5c199d89d3383768.md|Issue fin-5c199d89d3383768]]
#### Observations
- [[occurrences/occ-b9eac826a2717538.md|tags[cc]]]

### GET https://public-firing-range.appspot.com/tags/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9db983f88a998fe8.md|Issue fin-9db983f88a998fe8]]
#### Observations
- [[occurrences/occ-17cc95785cb66bb6.md|tags/index.html[cc]]]

### GET https://public-firing-range.appspot.com/urldom/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bb3bf2c5f1319c09.md|Issue fin-bb3bf2c5f1319c09]]
#### Observations
- [[occurrences/occ-7354d4b7b55f3d17.md|urldom[cc]]]

### GET https://public-firing-range.appspot.com/urldom/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-151861b6f511f358.md|Issue fin-151861b6f511f358]]
#### Observations
- [[occurrences/occ-f31506696f40255e.md|urldom/index.html[cc]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9a6e868a9fab1e2c.md|Issue fin-9a6e868a9fab1e2c]]
#### Observations
- [[occurrences/occ-1626990d8d4be41d.md|vulnerablelibraries[cc]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/index.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-65139e56b84c3043.md|Issue fin-65139e56b84c3043]]
#### Observations
- [[occurrences/occ-427de30b9d4507a5.md|vulnerablelibraries/index.html[cc]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2ac0d2f433e2023f.md|Issue fin-2ac0d2f433e2023f]]
#### Observations
- [[occurrences/occ-f331d2f14a8f66e2.md|jquery.html[cc]]]

