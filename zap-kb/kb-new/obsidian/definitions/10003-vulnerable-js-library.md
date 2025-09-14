---
aliases:
  - "VJL-0003"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10003"
name: "Vulnerable JS Library"
occurrenceCount: "0"
pluginId: "10003"
schemaVersion: "v1"
sourceTool: "zap"
---

# Vulnerable JS Library (Plugin 10003)

## Detection logic

- Logic: passive
- Add-on: retire
- Source path: `zap-extensions/addOns/retire/src/main/java/org/zaproxy/addon/retire/RetireScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/retire/src/main/java/org/zaproxy/addon/retire/RetireScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10003/

### How it detects

Passive; sets evidence

### References
- https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

