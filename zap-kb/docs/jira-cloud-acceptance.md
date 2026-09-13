# Jira publication contract and workplace acceptance

Local engineering date: 12 September 2026. Live Jira Cloud acceptance remains
pending: the owner has no personal tenant and no designated workplace test
credentials were available. No production publication is part of these checks.

## Observed published-container behavior

The coordinator resolved and tested the current GitHub `latest` image as
`ghcr.io/warlockobama/zap-kb-atlassian@sha256:465736677d25682c8be936d7521478636d6728c63266187e6b977a9646b7da24`.
It was built for amd64 on 6 August and carries no revision label. A disposable
Docker API stub and synthetic credentials established:

| Input and stub behavior | Observed published-image outcome |
| --- | --- |
| Environment-only site URL, successful create | Cloud search and create v3 endpoints; project TEST, type Bug, ADF document; created=1, exit 0 |
| Same site URL, create rejected with HTTP 400 | created=0, errors=1, **exit 0** |
| Environment-only `api.atlassian.com/ex/jira/mock-cloud` URL | Incorrect Data Center selection and v2 search; errors=1, **exit 0** |

The run artifact survived each scenario. These observations establish defects
in the currently published image. They do not establish which image digest,
credentials, permissions or required fields caused the historical workplace
failure; the owner cannot presently obtain that job's logs or digest. Assignment
08 owns corrected image identity; the coordinator retains the isolated harness
and exact before/after container evidence.

## API and configuration decisions

Cloud site roots and `https://api.atlassian.com/ex/jira/{cloudId}` select REST v3
and ADF. Scoped API tokens require the gateway; unscoped tokens use the site.
Basic authentication uses account email plus API token. The package also accepts
an already-issued OAuth bearer token when username is empty; it does not obtain
or refresh OAuth credentials. Data Center retains REST v2, wiki descriptions,
username/password Basic authentication and username-free bearer PATs.
[Atlassian token URL requirements](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/),
[Cloud authentication](https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/#authentication).

A gateway API root cannot yield a browser hostname. Configure the separate Jira
site root for human-facing issue links; never generate `/browse` links on the
gateway. Issue type accepts a name or numeric ID. Project-specific custom fields,
priority, parent, components and assignee can be configured on new finding
issues. A null optional override omits a default field, for example priority.
Overrides cannot change generated labels, identity, project/type, evidence or
workflow. Cloud assignee uses accountId; Data Center uses name. Existing Jira
workflow and assignee remain owned by Jira. Detection epics use Cloud parent;
requesting unsupported Data Center epics records a failure.

The optional read-only readiness check has a 20-second overall deadline and
5-second request deadline. It checks project Browse Projects/Create Issues
permissions, paginated issue-type metadata, and required create fields. Cloud
metadata arrays are `issueTypes` and `fields`; pagination follows actual returned
counts and total, including server page-size caps. A bounded check lists required
field IDs without copying names, evidence or arbitrary remote messages. It does
not require `/myself`, which has separate user-read scopes. Metadata requires
appropriate issue-meta/field-configuration read scopes; diagnostic access is
distinct from create permission. Passing these checks is **not** a successful
create test, and allowed values, assignment eligibility, field contexts and
parent hierarchy still require tenant acceptance.
[Create and metadata contracts](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/),
[Project permissions](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-permissions/).

## Failure and retry behavior

Search failures and malformed search responses prohibit create. Searches retain
current and legacy finding labels and are scoped to the configured project.
An explicit 429 rejection may retry up to three attempts, honoring a bounded
Retry-After. Transport errors, 5xx, missing keys or malformed successful create
responses trigger bounded search reconciliation. A recovered key is retained;
an unresolved outcome is an `ambiguous_create` failure and is never blindly
reposted. Jira search can lag recent writes; an empty result is not proof a
timed-out create failed. Inspect Jira before retrying an unresolved publication.
Do not run concurrent publishers against the same project/input: labels are
deduplication markers, not server-enforced unique keys.
[Enhanced search consistency](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/).

Diagnostics retain finding ID, stage, HTTP status, retryability and a static
actionable category. Only known field identifiers and numeric customfield IDs
survive; arbitrary server field names and values do not. Requested epic or
parent-link failures count even when flat finding creation succeeds. The common
publication result records required success, partial failure, failure and
deliberate skip; orchestration persists results and available evidence before
returning a required-stage failure.

## Designated-tenant acceptance procedure (pending access)

1. Obtain approval for one disposable project and test account. Record its Cloud
   site URL, cloud ID, token type/scopes, project key, issue type ID, required
   fields, parent/component constraints and assignee account ID. Keep credentials
   in the job's secret environment, never in commands or evidence files.
2. Pin the reviewed image by digest and retain its version/revision output. Run
   the read-only readiness check and save sanitized output; resolve configuration
   and required-field diagnostics before publishing.
3. Use one synthetic eligible finding with a unique stable finding ID and a
   scanner-native run artifact. Publish to the approved project with the
   configured type, required fields, parent and test assignee.
4. Read back the returned key. Verify project/type, labels, ADF evidence,
   configured parent/component and assignee. Re-publish the identical retained
   artifact after the successful key is persisted; verify one matching issue,
   no duplicate create, and unchanged Jira-owned status/assignment.
5. If Confluence is in scope, verify evidence cross-links and preserve a marked
   analyst block through repeat publication. Intentionally reject one destination
   at a time and verify the other destination gets its defined chance to finish.
6. Intentionally omit a required test-project field or use a forbidden test type.
   Verify nonzero exit, retained artifacts and sanitized finding/field diagnostic.
   Do not infer this intentional rejection is the historical workplace cause.
7. Retain digest, sanitized results, keys and readback assertions under workplace
   evidence-retention policy. Cleanup of disposable issues/pages is a separate
   approved workplace action. Mark live acceptance complete only after this run.
