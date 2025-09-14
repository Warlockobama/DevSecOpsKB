---
aliases:
  - "HIL-0032"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40032"
name: ".htaccess Information Leak"
occurrenceCount: "0"
pluginId: "40032"
schemaVersion: "v1"
sourceTool: "zap"
---

# .htaccess Information Leak (Plugin 40032)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/HtAccessScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/HtAccessScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40032/

### How it detects

Active

### References
- https://developer.mozilla.org/en-US/docs/Learn/Server-side/Apache_Configuration_htaccess
- https://httpd.apache.org/docs/2.4/howto/htaccess.html

