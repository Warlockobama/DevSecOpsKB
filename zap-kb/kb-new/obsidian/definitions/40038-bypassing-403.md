---
aliases:
  - "B4-0038"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40038"
name: "Bypassing 403"
occurrenceCount: "0"
pluginId: "40038"
schemaVersion: "v1"
sourceTool: "zap"
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

