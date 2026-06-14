# Forgejo Workflow Convention

How analyst workflow state is expressed on Forgejo, which only has a coarse
open/closed issue state instead of Jira's configurable workflow engine. The
gap is closed with a **label-state convention**: labels carry triage
granularity, open/closed carries resolution, and the sink maps both back to
the KB's canonical statuses.

## Source of truth

Forgejo Issues are the workflow source of truth for the Forgejo sink (the
analog of Jira in the Atlassian deployment). The KB is the evidence and
reporting surface:

- The sink creates one issue per qualifying finding (default `-forgejo-min-risk
  medium`; lower-severity findings opt in via the `case-ticket` analyst tag).
- The wiki (published with `-forgejo-wiki`) is the evidence view — the
  Confluence analog. Pages are machine-owned and overwritten on every publish.
- Analyst decisions live on the issue: comments, assignees, labels, and the
  open/closed state. Do **not** record workflow decisions by editing wiki
  pages or generated KB status fields.

## Canonical statuses and their label mapping

The KB recognizes five analyst statuses: `open`, `triaged`, `fixed`,
`accepted`, `fp`. On Forgejo they are expressed as:

| KB status  | Forgejo expression |
|------------|--------------------|
| `open`     | Issue open, no workflow label |
| `triaged`  | Issue open + a `triaged`, `in-progress`, `in-review`, `review`, or `under-review` label |
| `fixed`    | Issue **closed** (no fp/accepted label), or a `fixed`, `resolved`, `done`, or `completed` label |
| `accepted` | `accepted`, `risk-accepted`, `wontfix`, or `mitigated` label |
| `fp`       | `false-positive`, `fp`, `not-a-bug`, or `not-applicable` label |

Notes on the mapping (implemented in `internal/output/forgejo/status.go`):

- **Labels win over state.** A closed issue labeled `false-positive` maps to
  `fp`, not `fixed` — closing is how you end work, the label says *why*.
- Label matching is case-insensitive and separator-insensitive:
  `risk-accepted`, `risk_accepted`, and `Risk Accepted` are equivalent.
- When closing as anything other than fixed, **apply the label first, then
  close** (or in one edit) so an intervening status pull never reads the
  closed issue as `fixed`.

## Labels owned by the sink

The sink creates and manages these — do not repurpose them:

- `kb-finding` — marks an issue as KB-managed; the dedup scan is scoped to it.
- `risk/high`, `risk/medium`, `risk/low`, `risk/info` — severity, restamped
  from scanner data on every publish.
- Extra static labels from `-forgejo-labels` (e.g. a team or service tag).

Everything else on the issue is yours: assignees, milestones, comments,
additional labels, and the workflow labels above.

## Status flow back into the KB

- By default the publish performs a **read-only** status pull: it reports
  mapped statuses but does not mutate KB analyst fields (Forgejo stays the
  source of truth).
- With `-forgejo-sync-kb-status` the mapped status is written back into
  `analyst.status` and persisted to the entities file — use this only when a
  downstream consumer needs KB-side status snapshots.
- Issue bodies are machine-owned and refreshed on every run (evidence,
  occurrence counts, wiki links). Analyst commentary belongs in comments.
- A finding that recurs after its issue was closed gets the issue
  **reopened** with a comment, not a duplicate issue.

## Jira parity notes

| Jira capability | Forgejo answer |
|-----------------|----------------|
| Workflow states | Label-state convention above (open/closed + labels) |
| JQL / reporting | The KB itself: triage board, dashboard, executive summary pages |
| Assignment      | Native issue assignees |
| Automation      | Forgejo Actions + webhooks on label/state changes |
| Ticket links    | `owner/repo#N` refs in `analyst.ticketRefs`, linkified in the wiki |

Known non-goals: multi-step approval workflows and custom field schemes have
no Forgejo equivalent — keep those in the KB's governance fields (suppression
records, acceptance expiry) where they already live.
