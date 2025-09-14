---
aliases:
  - "SAIL-0042"
generatedAt: "2025-09-04T16:49:58Z"
id: "def-40042"
name: "Spring Actuator Information Leak"
occurrenceCount: "0"
pluginId: "40042"
schemaVersion: "v1"
sourceTool: "zap"
---

# Spring Actuator Information Leak (Plugin 40042)

## Detection logic

- Logic: active
- Add-on: ascanrules
- Source path: `zap-extensions/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SpringActuatorScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SpringActuatorScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/40042/

### How it detects

Active; uses regex patterns; sets evidence

Signals:
- regex:application\\/vnd\\.spring-boot\\.actuator\\.v[0-9]\\+json|application\\/json
- regex:\\{.*\\:.*\\}

### References
- https://docs.spring.io/spring-boot/docs/current/actuator-api/htmlsingle/#overview

