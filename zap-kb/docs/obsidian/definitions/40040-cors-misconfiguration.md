---
aliases:
  - "CM-0040"
cweId: "942"
cweUri: "https://cwe.mitre.org/data/definitions/942.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-40040"
name: "CORS Misconfiguration"
occurrenceCount: "4"
pluginId: "40040"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "4"
wascId: "14"
---

# CORS Misconfiguration (Plugin 40040)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/CorsScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/CorsScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40040/

### How it detects

Active; sets evidence

## Remediation

If a web resource contains sensitive information, the origin should be properly specified in the Access-Control-Allow-Origin header. Only trusted websites needing this resource should be specified in this header, with the most secured protocol supported.

### References
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- https://portswigger.net/web-security/cors

## Issues

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowNullOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-1153f3d4dd269609.md|Issue fin-1153f3d4dd269609]]
#### Observations
- [[occurrences/occ-35642cb53e7fd787.md|allowNullOrigin]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginEndsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7aec442f0d31abc3.md|Issue fin-7aec442f0d31abc3]]
#### Observations
- [[occurrences/occ-e288c897eeffcc95.md|allowOriginEndsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/allowOriginStartsWith  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-9ecd8293fef38b2f.md|Issue fin-9ecd8293fef38b2f]]
#### Observations
- [[occurrences/occ-74ce9db06b38ee36.md|allowOriginStartsWith]]

### POST https://public-firing-range.appspot.com/cors/alloworigin/dynamicAllowOrigin  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5faccd4114ed7e76.md|Issue fin-5faccd4114ed7e76]]
#### Observations
- [[occurrences/occ-8f4c50288fc11165.md|dynamicAllowOrigin]]

