---
aliases:
  - "PD-0025"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40025"
name: "Proxy Disclosure"
occurrenceCount: "0"
pluginId: "40025"
schemaVersion: "v1"
sourceTool: "zap"
---

# Proxy Disclosure (Plugin 40025)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ProxyDisclosureScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/ProxyDisclosureScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40025/

### How it detects

Active; uses regex patterns; strength: low

_strength: low_

Signals:
- regex:^<address>(.+)\\s+Server[^<]*</address>$
- regex:^Max-Forwards:\\s*([0-9]+)\\s*$

### References
- https://tools.ietf.org/html/rfc7231#section-5.1.2

