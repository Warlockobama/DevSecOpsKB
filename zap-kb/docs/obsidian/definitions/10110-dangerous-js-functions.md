---
aliases:
  - "DJF-0110"
cweId: "749"
cweUri: "https://cwe.mitre.org/data/definitions/749.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10110"
name: "Dangerous JS Functions"
occurrenceCount: "11"
pluginId: "10110"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "11"
---

# Dangerous JS Functions (Plugin 10110)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/JsFunctionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/JsFunctionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10110/

### How it detects

Passive; uses regex patterns; sets evidence

Signals:
- regex:\\b\\$?
  - hint: Regular expression; see pattern for details.

## Remediation

See the references for security advice on the use of these functions.

### References
- https://angular.io/guide/security
- https://v17.angular.io/guide/security

## Issues

### GET https://public-firing-range.appspot.com/address/location.hash/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-2ce012818a5e5f9f.md|Issue fin-2ce012818a5e5f9f]]
#### Observations
- [[occurrences/occ-cb9678d26d5e0b15.md|eval]]

### GET https://public-firing-range.appspot.com/address/location/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-538ae6b7a41472c2.md|Issue fin-538ae6b7a41472c2]]
#### Observations
- [[occurrences/occ-8caadaa8c2c3f8a3.md|eval]]

### GET https://public-firing-range.appspot.com/dom/dompropagation/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-c5cf49f34ecdafc6.md|Issue fin-c5cf49f34ecdafc6]]
#### Observations
- [[occurrences/occ-fa279d8b61cf0818.md|dompropagation]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/complexMessageDocumentWriteEval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6249d2b28350f8b5.md|Issue fin-6249d2b28350f8b5]]
#### Observations
- [[occurrences/occ-ef6fb88497efca61.md|complexMessageDocumentWriteEval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/eval  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-f1e91bf52873606c.md|Issue fin-f1e91bf52873606c]]
#### Observations
- [[occurrences/occ-d959b79255fe47df.md|eval]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithPartialStringComparison  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-662f2fe3e2664fa4.md|Issue fin-662f2fe3e2664fa4]]
#### Observations
- [[occurrences/occ-30aa5849fcf79f02.md|improperOriginValid…tialStringComparison]]

### GET https://public-firing-range.appspot.com/dom/toxicdom/postMessage/improperOriginValidationWithRegExp  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-919d014b4c6a0081.md|Issue fin-919d014b4c6a0081]]
#### Observations
- [[occurrences/occ-c7cae84174a1e3fc.md|improperOriginValidationWithRegExp]]

### GET https://public-firing-range.appspot.com/escape/js/encodeURIComponent?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-a42c8c26adb6ea75.md|Issue fin-a42c8c26adb6ea75]]
#### Observations
- [[occurrences/occ-b4e419687e57854a.md|encodeURIComponent]]

### GET https://public-firing-range.appspot.com/escape/js/escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d43ce3ae467bb063.md|Issue fin-d43ce3ae467bb063]]
#### Observations
- [[occurrences/occ-de20ffdafbb23ced.md|escape]]

### GET https://public-firing-range.appspot.com/escape/js/html_escape?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-445947d1c5af1cf2.md|Issue fin-445947d1c5af1cf2]]
#### Observations
- [[occurrences/occ-7fded10c94eb7636.md|html_escape]]

### GET https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1eb1168f8d18d3f1.md|Issue fin-1eb1168f8d18d3f1]]
#### Observations
- [[occurrences/occ-f546baf54dc7c46c.md|js_eval]]

