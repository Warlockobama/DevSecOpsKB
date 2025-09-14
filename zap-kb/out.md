# ZAP-KB Data Flow

```mermaid
flowchart LR
    subgraph ZAP["ZAP Runtime"]
      A[ZAP Scans]
      API[(ZAP API)]
      A --> API
    end

    subgraph Collector["zap-kb Collector (Go)"]
      C1[Fetch Alerts (paged by default)]
      C2[De-dup (deterministic key)]
      C3[Write JSON (source of truth)]
    end

    subgraph Overlays["Overlays (post-process)"]
      O1[Identity Overlay\n(UUIDv5 per Definition/Finding,\nULID per Occurrence)]
      O2[Enrichment Overlay\n(CWE/OWASP/NIST, tags, scoring)]
      O3[Temporal Overlay\n(first_seen, last_seen, counts)]
    end

    subgraph Stores["Data Stores"]
      JSN[(alerts.json)]
      DEF[(definitions.json)]
      FIND[(findings.json)]
      OCC[(occurrences.json)]
      INV[(investigations.json)]
    end

    subgraph Sinks["Human Outputs"]
      OBS[Obsidian Markdown]
      CONF[Confluence Pages]
      DASH[Dashboards (e.g., Grafana)]
    end

    API --> C1 --> C2 --> C3 --> JSN

    JSN --> O1 --> DEF
    JSN --> O1 --> FIND
    JSN --> O1 --> OCC

    JSN --> O2
    DEF --> O2
    FIND --> O2
    OCC --> O2

    O2 --> DEF
    O2 --> FIND
    O2 --> OCC

    JSN --> O3
    OCC --> O3
    O3 --> FIND

    DEF --> OBS
    FIND --> OBS
    OCC --> OBS
    INV --> OBS

    DEF --> CONF
    FIND --> CONF
    OCC --> CONF
    INV --> CONF

    DEF --> DASH
    FIND --> DASH
    OCC --> DASH
