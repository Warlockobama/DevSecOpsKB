---
aliases:
  - "SCDG-ef41"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-41"
name: "Source Code Disclosure - Git"
occurrenceCount: "0"
pluginId: "41"
schemaVersion: "v1"
sourceTool: "zap"
---

# Source Code Disclosure - Git (Plugin 41)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SourceCodeDisclosureGitScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SourceCodeDisclosureGitScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/41/

### How it detects

Active; uses regex patterns; sets evidence; strength: low

_strength: low_

Signals:
- regex:<%.*%>
- regex:<?php

### References
- https://owasp.org/www-community/attacks/Forced_browsing
- https://cwe.mitre.org/data/definitions/425.html

