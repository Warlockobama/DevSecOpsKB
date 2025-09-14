---
aliases:
  - "SF-0013"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40013"
name: "Session Fixation"
occurrenceCount: "0"
pluginId: "40013"
schemaVersion: "v1"
sourceTool: "zap"
---

# Session Fixation (Plugin 40013)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SessionFixationScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/SessionFixationScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40013/

### How it detects

Active

### References
- https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication
- https://owasp.org/www-community/attacks/Session_fixation
- https://acrossecurity.com/papers/session_fixation.pdf
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

