---
aliases:
  - "HPP-0014"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-20014"
name: "HTTP Parameter Pollution"
occurrenceCount: "0"
pluginId: "20014"
schemaVersion: "v1"
sourceTool: "zap"
---

# HTTP Parameter Pollution (Plugin 20014)

## Detection logic

- Logic: active
- Add-on: ascanrulesBeta
- Source path: `zap-extensions/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/HttpParameterPollutionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/HttpParameterPollutionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/20014/

### How it detects

Active

### References
- https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution

