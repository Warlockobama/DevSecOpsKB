---
aliases:
  - "IDIBS-0000"
cweId: "359"
cweUri: "https://cwe.mitre.org/data/definitions/359.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-120000"
name: "Information Disclosure - Information in Browser sessionStorage"
occurrenceCount: "15"
pluginId: "120000"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "15"
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

### GET https://www.google.com/search?client=firefox-b-d&q=google+firing+range  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6e97139792ba9d25.md|Issue fin-6e97139792ba9d25]]
#### Observations
- [[occurrences/occ-c928b57ebd0351fa.md|search[jjj]]]

### GET https://www.google.com/search?client=firefox-b-d&q=google+firing+range&sei=j_jJaNXSKOmMwbkP-Je1uAY  (observations: 9; open:9 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-870760a9ede23da9.md|Issue fin-870760a9ede23da9]]
#### Observations
- [[occurrences/occ-17f39d12d711bb89.md|search[ci]]]
- [[occurrences/occ-a36fffe3cdd7b403.md|search[h1]]]
- [[occurrences/occ-97cfcc244e97f5e0.md|search[h1]]]
- [[occurrences/occ-6d653e1699bb1bbc.md|search[swp]]]
- [[occurrences/occ-2ba90a7e42796b1f.md|search[swpth]]]
- [[occurrences/occ-7695d31b4a741ee1.md|search[swsp]]]
- [[occurrences/occ-867795ed024da405.md|search[swsd]]]
- [[occurrences/occ-f0478e1a28570b78.md|search[swzgws]]]
- [[occurrences/occ-c7628f5cd763cf6a.md|search[ule]]]

### GET https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dgoogle%2Bfiring%2Brange%26sei%3Dj_jJaNXSKOmMwbkP-Je1uAY&q=EgSB3qOYGJDxp8YGIjDveYUWABxXj37Uckg8e5nyxzUCm3Hoex3ej7Ur3nbuOglgQJYhcGkp8XUuNILWJFQyAVJaAUM  (observations: 5; open:5 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-b27160be4428583e.md|Issue fin-b27160be4428583e]]
#### Observations
- [[occurrences/occ-b7b432d971dd692f.md|index[g]]]
- [[occurrences/occ-b4e484eeec6bc906.md|index[ra]]]
- [[occurrences/occ-4e80bfc3d1f101c0.md|index[rb]]]
- [[occurrences/occ-bbbc9fa843cbe338.md|index[rc]]]
- [[occurrences/occ-d597b61dcca1148e.md|index[rf]]]

