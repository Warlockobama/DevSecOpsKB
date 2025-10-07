---
aliases:
  - "CDJSF-0017"
cweId: "829"
cweUri: "https://cwe.mitre.org/data/definitions/829.html"
generatedAt: "2025-09-21T20:00:10Z"
id: "def-10017"
name: "Cross-Domain JavaScript Source File Inclusion"
occurrenceCount: "26"
pluginId: "10017"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceTool: "zap"
status.open: "26"
wascId: "15"
---

# Cross-Domain JavaScript Source File Inclusion (Plugin 10017)

## Detection logic

- Logic: passive
- Add-on: pscanrules
- Source path: `zap-extensions/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CrossDomainScriptInclusionScanRule.java`
- GitHub: https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/CrossDomainScriptInclusionScanRule.java
- Docs: https://www.zaproxy.org/docs/alerts/10017/

### How it detects

Passive; sets evidence; threshold: low

_threshold: low_

## Remediation

Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

## Issues

### GET https://public-firing-range.appspot.com/angular/angular_body/1.1.5?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d8036357f125963d.md|Issue fin-d8036357f125963d]]
#### Observations
- [[occurrences/occ-56be9197412f0ead.md|1.1.5[agcala11]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-02fb1e6cb25cb809.md|Issue fin-02fb1e6cb25cb809]]
#### Observations
- [[occurrences/occ-5225d583679625fe.md|1.2.0[agcala12]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.18?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-324c43c30a985f5a.md|Issue fin-324c43c30a985f5a]]
#### Observations
- [[occurrences/occ-a24af874bd88909f.md|1.2.18[agcala12]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.19?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-90615e2279842ea5.md|Issue fin-90615e2279842ea5]]
#### Observations
- [[occurrences/occ-32f6d4a017205f2b.md|1.2.19[agcala12]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.2.24?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-dc9f39f2ba981611.md|Issue fin-dc9f39f2ba981611]]
#### Observations
- [[occurrences/occ-7f41e411b01d8335.md|1.2.24[agcala12]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3a0c3b76f33e11b6.md|Issue fin-3a0c3b76f33e11b6]]
#### Observations
- [[occurrences/occ-e3cc1ba0369d1b8b.md|1.4.0[agcala14]]]

### GET https://public-firing-range.appspot.com/angular/angular_body/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-aa448fc5b60dfbea.md|Issue fin-aa448fc5b60dfbea]]
#### Observations
- [[occurrences/occ-b45fd962dda58aba.md|1.6.0[agcala16]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3583d3eaf023878c.md|Issue fin-3583d3eaf023878c]]
#### Observations
- [[occurrences/occ-89d81695b025b83b.md|1.4.0[agcala14]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_alt_symbols_raw/1.6.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-bd54878e3a2a3d6d.md|Issue fin-bd54878e3a2a3d6d]]
#### Observations
- [[occurrences/occ-0532850c5bea5431.md|1.6.0[agcala16]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3c0e61642124225a.md|Issue fin-3c0e61642124225a]]
#### Observations
- [[occurrences/occ-92a394ced8ad4cff.md|1.4.0[agcala14]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-4244288964338393.md|Issue fin-4244288964338393]]
#### Observations
- [[occurrences/occ-9deeb5e3927849ca.md|1.4.0[agcala14]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_attribute_non_ng_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-54a7af289db630ee.md|Issue fin-54a7af289db630ee]]
#### Observations
- [[occurrences/occ-1f975a24c6c72248.md|1.4.0[agcala14]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-7fd4eb57d63c2857.md|Issue fin-7fd4eb57d63c2857]]
#### Observations
- [[occurrences/occ-83725ea948ac5652.md|1.4.0[agcala14]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d0d66fd13e917360.md|Issue fin-d0d66fd13e917360]]
#### Observations
- [[occurrences/occ-013e943ac30fa4f8.md|1.4.0[agcala14]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_escaped_alt_symbols/1.4.0?q=test  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-6ac6d721fb649444.md|Issue fin-6ac6d721fb649444]]
#### Observations
- [[occurrences/occ-ddf8d47336c89931.md|1.4.0[agcala14]]]

### GET https://public-firing-range.appspot.com/angular/angular_body_raw_post/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-716359990efa40bf.md|Issue fin-716359990efa40bf]]
#### Observations
- [[occurrences/occ-780ef0a658ad73fa.md|1.6.0[agcala16]]]

### GET https://public-firing-range.appspot.com/angular/angular_cookie_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3236335ab34ff90f.md|Issue fin-3236335ab34ff90f]]
#### Observations
- [[occurrences/occ-1325f98663ca8e72.md|1.6.0[agcala16]]]

### GET https://public-firing-range.appspot.com/angular/angular_form_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-3df502e9e5e36cb1.md|Issue fin-3df502e9e5e36cb1]]
#### Observations
- [[occurrences/occ-342e73d4cf484c89.md|1.6.0[agcala16]]]

### GET https://public-firing-range.appspot.com/angular/angular_post_message_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5cb89ed314139a4d.md|Issue fin-5cb89ed314139a4d]]
#### Observations
- [[occurrences/occ-95edcf2838d564d1.md|1.6.0[agcala16]]]

### GET https://public-firing-range.appspot.com/angular/angular_storage_parse/1.6.0  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-de3cbda3e6017e83.md|Issue fin-de3cbda3e6017e83]]
#### Observations
- [[occurrences/occ-12e0d6170e9a1991.md|1.6.0[agcala16]]]

### GET https://public-firing-range.appspot.com/escape/serverside/encodeUrl/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-0dba487bb1277df2.md|Issue fin-0dba487bb1277df2]]
#### Observations
- [[occurrences/occ-492e244b2e2ae7a4.md|attribute_script[higca]]]

### GET https://public-firing-range.appspot.com/escape/serverside/escapeHtml/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-ff4e9de4a114b06c.md|Issue fin-ff4e9de4a114b06c]]
#### Observations
- [[occurrences/occ-00f84ce30abccaa5.md|attribute_script[higca]]]

### GET https://public-firing-range.appspot.com/insecurethirdpartyscripts/third_party_scripts_without_subresource_integrity.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-69bf5a072c260b77.md|Issue fin-69bf5a072c260b77]]
#### Observations
- [[occurrences/occ-b53a60b708b7e96d.md|third_party_scripts…e_integrity.html[ng]]]

### GET https://public-firing-range.appspot.com/reflected/parameter/attribute_script?q=a  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-5541671eab7a72e3.md|Issue fin-5541671eab7a72e3]]
#### Observations
- [[occurrences/occ-fed5a582c9e484d7.md|attribute_script[higca]]]

### GET https://public-firing-range.appspot.com/remoteinclude/parameter/script?q=https://google.com  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-77b21891a2361f4c.md|Issue fin-77b21891a2361f4c]]
#### Observations
- [[occurrences/occ-f2ed9cb137bff27e.md|script[hgc]]]

### GET https://public-firing-range.appspot.com/vulnerablelibraries/jquery.html  (observations: 1; open:1 triaged:0 fp:0 accepted:0 fixed:0)

- [[findings/fin-d7bdcc2f8eb6b76c.md|Issue fin-d7bdcc2f8eb6b76c]]
#### Observations
- [[occurrences/occ-db7fc9ba5e1894f9.md|jquery.html[hcjcj181]]]

