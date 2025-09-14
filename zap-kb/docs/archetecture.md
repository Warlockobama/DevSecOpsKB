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
  DEF[(definitions.json)]
  FIND[(findings.json)]
  OCC[(occurrences.json)]
end

subgraph Overlays
  O1[Identity overlay]
  O2[Enrichment overlay]
  O3[Temporal overlay]
end

subgraph Sinks
  OBS[Obsidian]
  CONF[Confluence]
  DASH[Dashboards]
end

API --> C1 --> C2 --> C3 --> JSN
JSN --> O1 --> DEF
JSN --> O2
JSN --> O3
O2 --> DEF
O2 --> FIND
O2 --> OCC
O3 --> FIND
DEF --> OBS
FIND --> OBS
OCC --> OBS
DEF --> CONF
FIND --> CONF
OCC --> CONF
DEF --> DASH
FIND --> DASH
OCC --> DASH
