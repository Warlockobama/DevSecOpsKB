# Shared output redaction

`-redact` protects the emitted view of validated evidence. IDs are constructed
from original evidence first; redaction then derives a separate output view.
The same policy covers previews, flat alerts, entities, `run.json`, rendered
Markdown, reports, Jira/Confluence payloads, Forgejo payloads, and ZIP members.
Source input bytes are not edited by redaction.

## Mode matrix

| Mode | Structured evidence | Free text and producer metadata |
| --- | --- | --- |
| `domain` | Replace URL hosts and Host/authority header values; preserve URL paths | Replace hosts in embedded HTTP(S) URLs and JSON host/hostname/domain fields |
| `query` | Replace URL query values, including relative request targets and Referer/Origin values | Replace query values in names, curl, descriptions, notes, embedded URLs, and JSON query/queryParams values |
| `cookies` | Replace Cookie and Set-Cookie values in parsed and raw headers | Replace named cookie headers and curl cookie arguments in every modeled text field and JSON header objects |
| `auth` | Replace Authorization/Proxy-Authorization and URL user information | Replace named authorization headers and curl user/bearer arguments in text and JSON metadata |
| `headers` | Replace X-Api-Key, Api-Key, X-Auth-Token, X-Access-Token, Authentication | Apply the same named-header rule to text and structured JSON metadata |
| `body` | Omit request/response body snippets, attack/evidence payloads, and curl; retain byte counts and body hashes | Omit corresponding JSON payload subtrees regardless of value type; omit opaque non-JSON `other` payloads; retain non-payload trace fields |
| `notes` | Omit analyst notes/rationale, history notes, suppression reason, reproduction steps | Omit corresponding JSON note subtrees; omit preserved Confluence editable notes and free-form log prose, retaining published history rows and canonical decisions |
| `secrets` | Scrub email, JWT, long hexadecimal credential patterns and named password/token/secret assignments | Apply patterns across definitions, remediation, scanner evidence, analyst history, headers/bodies, and JSON-encoded metadata; omit named credential subtrees |

Aliases remain supported (`cookie`, `authorization`, `header`, `note`, `secret`,
`pii`, `credentials`). Unknown CLI modes fail before input/output or destination
operations. Pattern-based `secrets` cannot recognize every arbitrary opaque
secret; use `body` and `notes` to omit those evidence classes explicitly.
Malformed raw header lines fail closed. JSON-encoded metadata is decoded only
when the entire string is one JSON document; trace structure, exact numbers,
rule names, weights, and useful nonsensitive context survive.

Graph identity fields (`definitionId`, `findingId`, `occurrenceId`, their
references, analyst `entryId`, `pluginId`, `sourceid`), source tool, scan labels,
schema identifiers, body hashes, and commit IDs are intentionally retained.
They are correlation data, not credential storage; redaction never recomputes
them. Ordinary analyst status, owner, ticket references, and history survive
unless their text matches a requested mode. For example, `secrets` replaces an
email owner but preserves the decision and its entry ID.

## Retention and publisher defaults

`-run-alerts=keep` is the compatibility default: run artifacts retain alert
records. Retained alerts receive the same requested redaction as every other
shared representation. `-run-alerts=omit` excludes the optional alert array;
the normalized entities remain available for import. Neither setting can
restore sensitive values removed by `-redact`. There is no unredacted archive
escape hatch. Without `-redact`, local artifact evidence remains unchanged by
the output policy; callers choosing to retain private evidence must keep the
source in their own restricted storage.

Forgejo retains its `auth,cookies,headers,secrets` defaults. Additional
`-forgejo-redact` modes now **add to** those defaults. This intentionally fixes
the prior replacement behavior, where `-forgejo-redact=query` disabled cookie
and authorization protection. Explicit `off`/`none` disables the Forgejo
defaults only; it never undoes the shared `-redact` policy.

Fresh Confluence and Forgejo wiki snapshots contain only generated pages for
the current entity graph. The existing source-tool carry-forward rules still
apply: matching analyst metadata is merged from the local vault before
redaction; unrelated old pages and attachments are not published or archived.
Confluence server-owned analyst blocks remain preserved when notes redaction
is not requested. With `notes`, historical published date/risk/count/scan/link
rows and canonical decisions remain, while editable prose is omitted.

ZIP inputs consist of generated output files and a fresh rendered vault view.
An unused `-out` in Obsidian mode, unrelated vault files, symlinks, and the ZIP
itself cannot become archive members. Inventory precedes archive creation;
writer/final-file close errors propagate and incomplete archives are removed.

## Diagnostics and acceptance

Validation keeps its safe field/category diagnostics. Other local/transport
errors use `synccore.SafeError`: static timeout/cancellation/failure categories,
never arbitrary error strings, paths, request URLs, or response bodies.
`synccore.HTTPError` retains HTTP status and an allowlisted wiki-branch category,
not raw server text. The publication result package remains the destination
outcome contract; adapters may supply their own allowlisted fields/messages.

Tracked tests reproduce the original cookie/query leaks and cover raw/normalized
JSON, previews, Markdown, archived member contents, retention, strict modes,
metadata subtrees, repeat redaction, unchanged source bytes and IDs, local
Jira/Confluence/Forgejo failure payloads, decoded Forgejo wiki payloads, and
Confluence/Obsidian analyst carry-forward. All credentials and services in
these tests are synthetic and local. No workplace tenant, production sink,
deployment, pruning, or live scan is exercised. Live destination acceptance
remains part of the designated pilot procedure.
