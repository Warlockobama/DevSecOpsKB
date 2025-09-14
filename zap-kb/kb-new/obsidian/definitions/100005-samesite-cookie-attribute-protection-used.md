---
aliases:
  - "SCAPU-0005"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-100005"
name: "SameSite Cookie Attribute Protection Used"
occurrenceCount: "0"
pluginId: "100005"
schemaVersion: "v1"
sourceTool: "zap"
---

# SameSite Cookie Attribute Protection Used (Plugin 100005)

## Detection logic

- Logic: passive
- Add-on: community-scripts
- Source path: `community-scripts/passive/detect_samesite_protection.js`
- GitHub: https://github.com/zaproxy/community-scripts/blob/main/passive/detect_samesite_protection.js
- Docs: https://www.zaproxy.org/docs/alerts/100005/

### References
- https://tools.ietf.org/html/draft-west-first-party-cookies
- https://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue

