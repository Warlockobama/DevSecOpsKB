```mermaid
flowchart LR
subgraph ZAP
  A[Scans] --> API[(API)]
end

subgraph Collector
  C1[Fetch Alerts] --> C2[De-dup] --> C3[Write JSON]
end

subgraph Stores
  JSN[(alerts.json)]
  ENT[(entities.json)]
  RUN[(run.json)]
end

subgraph Overlays
  O1["Identity overlay (scan.label in IDs)"]
  O2["Enrichment overlay (taxonomy: CWE/CAPEC/ATT&CK/NIST/OWASP; detection; remediation)"]
  O3["Temporal overlay (observedAt, firstSeen/lastSeen)"]
  O4["Triage overlay (analyst.*, status)"]
end

subgraph Sinks
  OBS["Obsidian vault (INDEX, DASHBOARD, triage-board, by-domain, findings, occurrences, definitions)"]
  REP["Reports (markdown)"]
  DASH["Dashboards/embeds"]
  CONF["Confluence (planned)"]
end

API --> C1 --> C2 --> C3 --> JSN
JSN --> ENT
ENT --> O1 --> O2 --> O3 --> O4 --> OBS
ENT --> RUN
RUN --> OBS
ENT --> REP
ENT --> DASH
ENT --> CONF
