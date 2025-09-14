---
aliases:
  - "S-0045"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40045"
name: "Spring4Shell"
occurrenceCount: "0"
pluginId: "40045"
schemaVersion: "v1"
sourceTool: "zap"
---

# Spring4Shell (Plugin 40045)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/Spring4ShellScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/Spring4ShellScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40045/

### How it detects

Active; checks headers: Form-Urlencoded-Content-Type, Crlf; sets evidence

Signals:
- header:Form-Urlencoded-Content-Type
- header:Crlf

### References
- https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/
- https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement#vulnerability
- https://tanzu.vmware.com/security/cve-2022-22965

