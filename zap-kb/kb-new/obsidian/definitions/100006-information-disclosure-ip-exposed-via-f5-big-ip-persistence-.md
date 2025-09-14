---
aliases:
  - "IDIEV-0006"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-100006"
name: "Information Disclosure - IP Exposed via F5 BIG-IP Persistence Cookie"
occurrenceCount: "0"
pluginId: "100006"
schemaVersion: "v1"
sourceTool: "zap"
---

# Information Disclosure - IP Exposed via F5 BIG-IP Persistence Cookie (Plugin 100006)

## Detection logic

- Logic: passive
- Add-on: community-scripts
- Source path: `community-scripts/passive/f5_bigip_cookie_internal_ip.js`
- GitHub: https://github.com/zaproxy/community-scripts/blob/main/passive/f5_bigip_cookie_internal_ip.js
- Docs: https://www.zaproxy.org/docs/alerts/100006/

### References
- https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html

