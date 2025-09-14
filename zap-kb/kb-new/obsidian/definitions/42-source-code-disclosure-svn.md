---
aliases:
  - "SCDS-ef42"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-42"
name: "Source Code Disclosure - SVN"
occurrenceCount: "0"
pluginId: "42"
schemaVersion: "v1"
sourceTool: "zap"
---

# Source Code Disclosure - SVN (Plugin 42)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SourceCodeDisclosureSvnScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SourceCodeDisclosureSvnScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/42/

### How it detects

Active; uses regex patterns; sets evidence; threshold: low; strength: low

_threshold: low; strength: low_

Signals:
- regex:<%.*%>
- regex:<\\?php

### References
- https://owasp.org/www-community/attacks/Forced_browsing
- https://cwe.mitre.org/data/definitions/425.html

