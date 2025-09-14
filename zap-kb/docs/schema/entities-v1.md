# Entities Schema v1

Goals
- Tool-agnostic: ZAP today, expand to Burp, SAST/DAST later.
- Stable deterministic IDs for reproducibility.
- Avoid duplication by separating Definition (static) / Finding (endpoint) / Occurrence (instance).
- Support enrichment (CWE → MITRE CAPEC/ATT&CK/NIST/OWASP) and remediation guidance.
- Preserve room for request/response summaries and analyst notes.

Top-level
- schemaVersion: "v1"
- generatedAt: RFC3339 UTC
- sourceTool: e.g., "zap"
- definitions: shared metadata for a rule/check
- findings: grouped by (pluginId, url, method)
- occurrences: individual instances

IDs (deterministic, short)
- definitionId = "def-"+pluginId
- findingId = "fin-"+sha1_8(pluginId|url|method)
- occurrenceId = "occ-"+sha1_8(pluginId|url|method|param|riskcode|confidence|attack|evidence)

Definition
- pluginId, alert, name, wascid
- taxonomy: { cweid, cweUri, capecIds[], attack[], owaspTop10[], nist80053[], tags[] }
- remediation: { summary, references[], guidance[], exampleFixes[] }
- detection (optional): { logicType, pluginRef, ruleSource, docsUrl, sourceUrl, matchReason }
 - detection (optional): { logicType, pluginRef, ruleSource, docsUrl, sourceUrl, matchReason, summary, signals[], defaults{threshold,strength} }

Finding
- definitionId, pluginId, url, method
- name (human-readable, e.g., "GET https://example.com/login")
- risk, riskcode, confidence (rollup)
- occurrenceCount

Occurrence
- occurrenceId, definitionId, findingId
- name (human-readable, e.g., "GET /login param=user ev="...") 
- url, method, param, attack, evidence, risk, riskcode, confidence, sourceid
- request { headers[], bodyHash, bodyBytes, bodySnippet } (optional)
- response { statusCode, headers[], bodyHash, bodyBytes, bodySnippet } (optional)
- analyst { status, owner, tags[], notes, ticketRefs[], updatedAt } (optional)

Large payloads
- By default, store only hashes and sizes for bodies; snippets are opt-in with future flags and redaction.

Enrichment
- A future enrichment step populates taxonomy mappings and expands remediation guidance.
- Optional detection enrichment can link a rule to its implementation and docs:
  - logicType: passive|active|unknown (inferred from rule path)
  - ruleSource: repo-like path in zap-extensions
  - sourceUrl: GitHub blob URL to the Java class
  - docsUrl: ZAP alert documentation page
  - summary/signals/defaults: best-effort hints parsed from the rule class (headers checked, regexes, threshold/strength)
