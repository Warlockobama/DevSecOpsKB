---
aliases:
  - "XAVR-0061"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10061"
name: "X-AspNet-Version Response Header"
occurrenceCount: "0"
pluginId: "10061"
schemaVersion: "v1"
sourceTool: "zap"
---

# X-AspNet-Version Response Header (Plugin 10061)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XAspNetVersionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/XAspNetVersionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10061/

### How it detects

Passive; sets evidence

### References
- https://www.troyhunt.com/shhh-dont-let-your-response-headers/
- https://blogs.msdn.microsoft.com/varunm/2013/04/23/remove-unwanted-http-response-headers/

