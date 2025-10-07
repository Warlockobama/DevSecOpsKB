---
aliases:
  - "UAF-0104"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10104"
name: "User Agent Fuzzer"
occurrenceCount: "36"
pluginId: "10104"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "36"
---

# User Agent Fuzzer (Plugin 10104)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/UserAgentScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/UserAgentScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10104/

### How it detects

Active

### References
- https://owasp.org/wstg

## Issues

### GET https://public-firing-range.appspot.com/leakedcookie/leakedcookie  (observations: 12; open:12 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c1ff9e373d2ef805.md|Issue fin-c1ff9e373d2ef805]]
#### Observations
- [[occurrences/occ-a7413039c7d81721.md|leakedcookie[hua]]]
- [[occurrences/occ-1d40824a5b1a1a54.md|leakedcookie[hua]]]
- [[occurrences/occ-7b88f67be1ca346b.md|leakedcookie[hua]]]
- [[occurrences/occ-322a90fd3845c1f2.md|leakedcookie[hua]]]
- [[occurrences/occ-f58f7e7159a7d93e.md|leakedcookie[hua]]]
- [[occurrences/occ-44802c67299b72f1.md|leakedcookie[hua]]]
- [[occurrences/occ-8e7379c848cc7e7c.md|leakedcookie[hua]]]
- [[occurrences/occ-0bf78c9a9dc87009.md|leakedcookie[hua]]]
- [[occurrences/occ-d7e70b95c92b377d.md|leakedcookie[hua]]]
- [[occurrences/occ-a06af7f71996aad1.md|leakedcookie[hua]]]
- [[occurrences/occ-758be9a1f1d15a21.md|leakedcookie[hua]]]
- [[occurrences/occ-e7c8f61ba0a4e940.md|leakedcookie[hua]]]

### GET https://public-firing-range.appspot.com/redirect/parameter/NOSTARTSWITHJS?url=/  (observations: 12; open:12 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ece6931d280c6e37.md|Issue fin-ece6931d280c6e37]]
#### Observations
- [[occurrences/occ-23263fe413cd50f8.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-710292be727cd411.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-715b8523ee0efa7e.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-fdc1c0ba0af3184a.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-e88bfb48d311aa0e.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-35dcced25e5da605.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-8e755885f6ea5c9d.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-e475da89904b3ba1.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-1bedcff3ab25f524.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-04e2aa821aa0febd.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-b03039c6ddc721b4.md|NOSTARTSWITHJS[hua]]]
- [[occurrences/occ-68e4cca2af13de1e.md|NOSTARTSWITHJS[hua]]]

### GET https://public-firing-range.appspot.com/redirect/parameter?url=/  (observations: 12; open:12 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ca6ab1581b936359.md|Issue fin-ca6ab1581b936359]]
#### Observations
- [[occurrences/occ-507e407a1a71ca9a.md|parameter[hua]]]
- [[occurrences/occ-4c8e0a95bd41e26c.md|parameter[hua]]]
- [[occurrences/occ-ca017db848488974.md|parameter[hua]]]
- [[occurrences/occ-065f38af03b7f38c.md|parameter[hua]]]
- [[occurrences/occ-b246246a1dfe5eb6.md|parameter[hua]]]
- [[occurrences/occ-fe59105a87e123c5.md|parameter[hua]]]
- [[occurrences/occ-f379d2397b1da50c.md|parameter[hua]]]
- [[occurrences/occ-a1eea6b9bd0ae7c1.md|parameter[hua]]]
- [[occurrences/occ-9a0727901387501e.md|parameter[hua]]]
- [[occurrences/occ-7987cc956e837754.md|parameter[hua]]]
- [[occurrences/occ-67519c445e6f83ae.md|parameter[hua]]]
- [[occurrences/occ-2d9814cbaec48495.md|parameter[hua]]]

