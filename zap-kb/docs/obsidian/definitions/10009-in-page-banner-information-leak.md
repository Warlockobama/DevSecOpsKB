---
aliases:
  - "PBIL-0009"
generatedAt: "2025-09-04T00:31:04Z"
id: "def-10009"
name: "In Page Banner Information Leak"
occurrenceCount: "0"
pluginId: "10009"
schemaVersion: "v1"
sourceTool: "zap"
---

# In Page Banner Information Leak (Plugin 10009)

## Detection logic

- Logic: passive
- Add-on: pscanrulesBeta
- Source path: `zap-extensions/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/InPageBannerInfoLeakScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/java/org/zaproxy/zap/extension/pscanrulesBeta/InPageBannerInfoLeakScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10009/

### How it detects

Passive; uses regex patterns; sets evidence; threshold: low

_threshold: low_

Signals:
- regex:Tomcat\\/\\d\\.\\d\\.\\d{1,2}
- regex:Apache\\/\\d\\.\\d\\.\\d{1,2}

