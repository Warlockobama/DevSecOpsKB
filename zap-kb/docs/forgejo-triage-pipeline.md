# Forgejo Browse-and-Triage Pipeline

An agent-driven loop where a Claude subagent opens a **real browser**, navigates
the Forgejo Issues board that `zap-kb` published findings to, and triages each
finding the way a human analyst would — reading evidence, judging
true-positive vs false-positive, and recording the verdict with Forgejo's
label-state convention. Forgejo stays the workflow source of truth; the KB is
the evidence surface.

```
  zap-kb scan/report            forgejo sink              forgejo-triager agent           KB
 ┌──────────────────┐   issues  ┌──────────────┐  Chrome  ┌────────────────────┐  status  ┌──────────┐
 │ entities.json    │ ────────▶ │  Forgejo     │ ───────▶ │ browse issues      │ ───────▶ │ analyst. │
 │ (findings)       │  +labels  │  Issues tab  │   MCP    │ judge → label/close│  pull    │ status   │
 └──────────────────┘           └──────────────┘          │ comment rationale  │          └──────────┘
        Stage 2                     Stage 1                 └────────────────────┘            Stage 5
                                                                  Stages 3–4
```

## Components
| Piece | Path | Role |
|---|---|---|
| Forgejo sink (local) | [`docker/docker-compose.forgejo.yml`](../docker/docker-compose.forgejo.yml) | A real, browseable Forgejo to triage against |
| Publisher | `zap-kb` root command, `-forgejo-*` flags | Creates one issue per finding (`internal/output/forgejo`) |
| Triager agent | [`.claude/agents/forgejo-triager.md`](../../.claude/agents/forgejo-triager.md) | Drives Chrome, judges, applies the label-state verdict |
| Workflow contract | [`docs/forgejo-workflow.md`](forgejo-workflow.md) | The label↔status mapping the agent enforces |
| One-shot helper | [`scripts/forgejo-triage.ps1`](../scripts/forgejo-triage.ps1) | Wraps the non-browser bookends (publish + status pull) |

## Prerequisites
- Docker (for the local Forgejo) — or any Forgejo/Gitea instance you can reach.
- A built `zap-kb` (`make build`) and an **entities file with findings** (from a
  prior scan — see [`docs/container.md`](container.md) for the scan step).
- The **Claude-in-Chrome extension connected and logged in** to the Forgejo
  instance. The agent reads and clicks through this extension; it will not log
  in for you.

---

## Stage 1 — Stand up the Forgejo sink
```bash
docker compose -f zap-kb/docker/docker-compose.forgejo.yml up -d
# wait for http://localhost:3000 to answer, then:
docker compose -f zap-kb/docker/docker-compose.forgejo.yml exec forgejo \
  forgejo admin user create --admin --username analyst \
    --password 'analyst-pw' --email analyst@example.com
TOKEN=$(docker compose -f zap-kb/docker/docker-compose.forgejo.yml exec -T forgejo \
  forgejo admin user generate-access-token --username analyst --raw \
    --scopes 'write:issue,write:repository')
```
Create the target repo (UI at `http://localhost:3000`, or API):
```bash
curl -fsS -X POST -H "Authorization: token $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"security-findings","private":false}' \
  http://localhost:3000/api/v1/user/repos
```
You now have `analyst/security-findings` and a token with issue+repo write.

## Stage 2 — Publish findings as issues
Run the publisher against your entities file. The `-forgejo-*` flags turn on the
sink; `-forgejo-issues` (default) creates one issue per qualifying finding.
```bash
export FORGEJO_TOKEN="$TOKEN"
zap-kb \
  -entities-in out/entities.json \
  -forgejo-url   http://localhost:3000 \
  -forgejo-owner analyst \
  -forgejo-repo  security-findings \
  -forgejo-min-risk medium \
  -forgejo-issues
  # add -forgejo-wiki to also publish the evidence vault as wiki pages
  # add -forgejo-dry-run first to preview which issues would be created
```
Each issue gets `kb-finding` + a `risk/<level>` label and a machine-owned body
(Risk/Confidence/Occurrences → Description → Remediation → Security
classification → Evidence). Re-running reconciles: bodies refresh, recurring
finds reopen, nothing is duplicated.

## Stage 3 — Connect Chrome
Open the Forgejo instance in the browser where the Claude-in-Chrome extension is
installed, and sign in as `analyst`. Confirm you can see
`http://localhost:3000/analyst/security-findings/issues`.

## Stage 4 — Run the triager
Spawn the **`forgejo-triager`** agent with the instance coordinates and a mode.
Default `recommend` is read-only (browse + report); `apply` also enacts verdicts.

> Use the forgejo-triager agent to triage the Forgejo board at
> `http://localhost:3000`, owner `analyst`, repo `security-findings`, mode `recommend`.

The agent: filters to `kb-finding`, opens each issue, reads the evidence,
decides `triaged` / `fp` / `accepted` (rarely `fixed` on first pass), and — in
`apply` mode — applies the label, comments the rationale, and closes per the
convention (**label before close**, **labels win over state**, **never edit the
machine-owned body/wiki**, **never touch `kb-finding`/`risk/*`**). It returns a
verdict table plus a "needs human decision" list for anything it can't call
(e.g. evidence scrubbed by redaction).

Review the report. Re-run in `apply` mode (or apply specific issue numbers
yourself) once you're happy with the recommendations.

## Stage 5 — Reconcile status back to the KB
The KB doesn't need mutating — Forgejo is the source of truth — but you can pull
the mapped statuses for KB-side reporting:
- A normal re-publish does a **read-only status pull** and reports the mapped
  `open|triaged|fixed|accepted|fp` per issue.
- Add **`-forgejo-sync-kb-status`** to persist the mapped status into
  `analyst.status` in the entities file (use only when a downstream consumer
  needs KB-side snapshots).
```bash
zap-kb \
  -entities-in out/entities.json \
  -forgejo-url http://localhost:3000 -forgejo-owner analyst -forgejo-repo security-findings \
  -forgejo-sync-kb-status
```

---

## Label-state cheat sheet (what the agent applies)
| Verdict | Forgejo action |
|---|---|
| `triaged` | open + `triaged` (or `in-progress`/`in-review`/`review`/`under-review`) |
| `fp` | `false-positive` (`fp`/`not-a-bug`/`not-applicable`) label, then close |
| `accepted` | `accepted` (`risk-accepted`/`wontfix`/`mitigated`) label, then close |
| `fixed` | close with no fp/accepted label, or `fixed`/`resolved`/`done` label |

Matching is case- and separator-insensitive (`risk-accepted` == `Risk Accepted`).
Sink-owned labels `kb-finding` and `risk/*` are restamped every publish — leave
them alone. Rationale goes in **comments**, never the body.

## Caveats
- **Browser tier**: the Claude-in-Chrome MCP must be connected; computer-use
  screenshots see browsers at "read" tier, so all clicking goes through the
  Chrome extension, not raw mouse control.
- **Link safety**: evidence can contain attacker-influenced URLs. The agent will
  not open external links in the browser — neither should you.
- **Point it at the right place**: run `apply` against a local or staging Forgejo
  first. Only triage a production tracker when you explicitly intend to.
