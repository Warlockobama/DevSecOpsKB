---
aliases:
  - "IDIBS-0000"
cweId: "359"
cweUri: "https://cwe.mitre.org/data/definitions/359.html"
generatedAt: "2025-01-01T00:00:00Z"
id: "def-120000"
name: "Information Disclosure - Information in Browser sessionStorage"
occurrenceCount: "14"
pluginId: "120000"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "14"
wascId: "13"
---

# Information Disclosure - Information in Browser sessionStorage (Plugin 120000)

## Detection logic

- Logic: passive
- Add-on: client
- Source path: `zap-extensions/addOns/client/src/main/java/org/zaproxy/addon/client/pscan/InformationInStorageScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/client/src/main/java/org/zaproxy/addon/client/pscan/InformationInStorageScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/120000/

### How it detects

Passive

## Remediation

This is an informational alert and no action is necessary.

## Issues

### GET https://www.google.com/search?client=firefox-b-d&q=firing+range+appspot+google  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1b126eec320b8ff9.md|Issue fin-1b126eec320b8ff9]]
#### Observations
- [[occurrences/occ-50c56e6b1939561c.md|search[1]]]

### GET https://www.google.com/search?client=firefox-b-d&q=firing+range+appspot+google&sei=1YacaIjPJJPZ5NoPjJeowAY  (observations: 8; open:8 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-72c38c803671c7d9.md|Issue fin-72c38c803671c7d9]]
#### Observations
- [[occurrences/occ-4a5f2fd2e8e85b79.md|search[ci]]]
- [[occurrences/occ-cbe27f6d32dbb009.md|search[h1]]]
- [[occurrences/occ-ee4a142b86152fa0.md|search[h1]]]
- [[occurrences/occ-19fc0ebe3dcaaedf.md|search[swp]]]
- [[occurrences/occ-828cb5bd1653e5f1.md|search[swpth]]]
- [[occurrences/occ-54a6d626b2122aaf.md|search[swsp]]]
- [[occurrences/occ-7e579549fe454d4a.md|search[swsd]]]
- [[occurrences/occ-751bb455ad885732.md|search[swzgws]]]

### GET https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dfiring%2Brange%2Bappspot%2Bgoogle%26sei%3D1YacaIjPJJPZ5NoPjJeowAY&q=EgSB3gKOGNaN8sQGIjCFSCeM0u9S-7on-GEdGlp-Ew3dmmCNrLA9xJYvRVI2IklgWlDfnCj8DKapVWJqXccyAVJaAUM  (observations: 5; open:5 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a9423f04c5999339.md|Issue fin-a9423f04c5999339]]
#### Observations
- [[occurrences/occ-a70fd58cf6a574ff.md|index[g]]]
- [[occurrences/occ-a5f1a8e1cac81f77.md|index[ra]]]
- [[occurrences/occ-c224165cb81f83be.md|index[rb]]]
- [[occurrences/occ-55f0541145297b5c.md|index[rc]]]
- [[occurrences/occ-f046e88fa3833fbc.md|index[rf]]]

