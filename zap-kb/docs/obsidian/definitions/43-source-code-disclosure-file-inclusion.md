---
aliases:
  - "SCDFI-ef43"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-43"
name: "Source Code Disclosure - File Inclusion"
occurrenceCount: "0"
pluginId: "43"
schemaVersion: "v1"
sourceTool: "zap"
---

# Source Code Disclosure - File Inclusion (Plugin 43)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SourceCodeDisclosureFileInclusionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SourceCodeDisclosureFileInclusionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/43/

### How it detects

Active; uses regex patterns; strength: insane

_strength: insane_

Signals:
- regex:<%.*%>
- regex:<?php

