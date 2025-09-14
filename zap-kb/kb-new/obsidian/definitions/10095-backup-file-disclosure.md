---
aliases:
  - "BFD-0095"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-10095"
name: "Backup File Disclosure"
occurrenceCount: "0"
pluginId: "10095"
schemaVersion: "v1"
sourceTool: "zap"
---

# Backup File Disclosure (Plugin 10095)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/BackupFileDisclosureScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/BackupFileDisclosureScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10095/

### How it detects

Active; threshold: low

_threshold: low_

### References
- https://cwe.mitre.org/data/definitions/530.html
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html

