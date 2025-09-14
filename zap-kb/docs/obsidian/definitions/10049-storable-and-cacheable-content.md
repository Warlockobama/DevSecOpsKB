---
aliases:
  - "SCC-0049"
cweId: "524"
cweUri: "https://cwe.mitre.org/data/definitions/524.html"
generatedAt: "2025-01-01T00:00:00Z"
id: "def-10049"
name: "Storable and Cacheable Content"
occurrenceCount: "1"
pluginId: "10049"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "1"
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

