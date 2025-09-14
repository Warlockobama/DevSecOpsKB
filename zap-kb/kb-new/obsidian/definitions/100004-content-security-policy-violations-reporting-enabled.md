---
aliases:
  - "CSPVR-0004"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-100004"
name: "Content Security Policy Violations Reporting Enabled"
occurrenceCount: "0"
pluginId: "100004"
schemaVersion: "v1"
sourceTool: "zap"
---

# Content Security Policy Violations Reporting Enabled (Plugin 100004)

## Detection logic

- Logic: passive
- Add-on: community-scripts
- Source path: `community-scripts/passive/detect_csp_notif_and_reportonly.js`
- GitHub: https://github.com/zaproxy/community-scripts/blob/main/passive/detect_csp_notif_and_reportonly.js
- Docs: https://www.zaproxy.org/docs/alerts/100004/

### References
- https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_CSP_violation_reports

