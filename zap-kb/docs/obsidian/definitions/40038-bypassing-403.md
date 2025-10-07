---
aliases:
  - "B4-0038"
cweId: "348"
cweUri: "https://cwe.mitre.org/data/definitions/348.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-40038"
name: "Bypassing 403"
occurrenceCount: "1"
pluginId: "40038"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "1"
---

# Bypassing 403 (Plugin 40038)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ForbiddenBypassScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ForbiddenBypassScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40038/

### How it detects

Active

### References
- https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/
- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
- https://www.contextis.com/en/blog/server-technologies-reverse-proxy-bypass
- https://seclists.org/fulldisclosure/2011/Oct/273

## Issues

### GET https://public-firing-range.appspot.com/reflected/parameter/body/403%20/  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-95b7db314d6d4fd2.md|Issue fin-95b7db314d6d4fd2]]
#### Observations
- [[occurrences/occ-c72a1d5a9c3f7990.md|403]]

