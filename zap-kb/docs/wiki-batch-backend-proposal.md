# Next measured wiki algorithm: opt-in Git batch publication

Status: implementation-ready proposal, not an adopted backend or rollout.
Assignment 06's default REST optimization remains useful but does not establish
large-wiki readiness. See [measurements](wiki-performance-2026-09.md).

## Decision and evidence

Prototype an explicitly selected Git batch backend after redaction and common
publication results land. Keep REST as the default until the prototype passes the
acceptance below. Do not add an automatically selected backend or silently switch
an existing destination.

An unchanged 5,000-page synthetic run still needs 5,102 REST requests after the
first optimization. Fresh encoded-link publication still makes 9,999 mutations in
that workload. In the disposable v9 five-version-per-page 1,000-page dataset, the
initial listing alone consumed 53.94 seconds; the 60-second unchanged call read
only 49 page bodies and made no mutations. The real 100-page fresh publish took
78.18 seconds and 199 Git commits. These are separate measured workloads, not a
linear extrapolation to production. They justify investigating elimination of
both metadata traversals and per-page writes, rather than only increasing workers.

A durable REST content manifest is not the next choice: trusting it would conceal
remote edits/deletes/renames unless backed by a remote revision snapshot. A bulk
Git snapshot already provides that revision and all content. A read-only Git plus
REST-write hybrid would remove expensive reads but retain fresh link repair and
many individual commits; batch Git addresses both measured costs.

The 5,000-page/25,000-commit snapshot adds direct bulk-read evidence: all page blobs
(21.9 MB including batch framing) read through local Docker/Git in 2.4–2.8 seconds,
while the REST publisher exhausted three 15-second attempts at its first 50-page
listing without reading any page content. This does not measure authenticated
network fetch or push and does not establish prototype throughput. The packed
storage and current Git versions are recorded with the main measurements.

## Package boundary

Add an explicit backend option at the Forgejo publisher boundary, default `rest`.
Have both backends return the established `WikiSummary` plus common sanitized
publication outcome. Reuse the existing generated, redacted vault and mapping of
vault-relative files to published page titles. Do not duplicate entity rendering,
identity logic, shared result types or redaction rules. Assignment 09 can extract
the shared vault collection/link-rendering boundary after contracts settle.

Discover the wiki clone URL and its symbolic HEAD from the configured repository
and remote, and validate they belong to that destination. Never assume that the
repository's default branch is the wiki branch. Bootstrap an empty wiki through
the existing supported REST path if required. Fail clearly on the known v9 empty
wiki-branch bug; this design does not authorize changing live repository settings.

The filename/title/web-path conversion must be an explicit, tested compatibility
module. Preserve existing server-compatible Git filenames and derive encoded
cross-links before committing. Fail on ambiguous title collisions. Test the
conversion against real server-issued paths on each supported Forgejo version;
do not assume ordinary URL PathEscape reproduces Forgejo's slash, dash marker,
space, plus, percent, Unicode and fragment behavior.

## Transaction and concurrency algorithm

1. Fetch the wiki into a temporary private workspace under a bounded context.
   Record branch and commit SHA. Read the full tree and required blobs in bulk.
2. Preserve all non-KB files exactly. Without an explicit prune option, preserve
   absent KB pages too. Render desired managed content and all internal links
   against the combined current/desired page map.
3. Compare exact bytes. If no managed content differs, verify that the remote
   branch still has the fetched SHA. Report a no-op only when that check succeeds;
   if the remote changed, fetch and reevaluate within the conflict budget.
4. Construct one commit containing only intended changed managed pages. Retain
   external files, their modes, and unchanged blobs. A one-page change must touch
   only that page unless an index/link's rendered bytes actually differ.
5. Push normally, without force. The fetched SHA is the parent, so a concurrent
   advance rejects the push. On rejection, fetch the new remote and recompute the
   intended managed changes once; never merge an old generated tree over new
   analyst content blindly. A second conflict returns a partial/failed outcome.
6. After success, confirm the remote branch contains the resulting commit and
   perform bounded encoded-link/API readback. On an ambiguous push response,
   reconcile the remote commit before retrying. If the commit is already present,
   do not create another commit. If the state cannot be established, report the
   ambiguity rather than success or a blind force push.
7. Remove temporary credentials and the private workspace on all exits. If
   cleanup fails, report the sanitized cleanup failure. Keep the redacted source
   artifact available independently of the Git workspace.

Limit each Git command, the total pass, and conflict/reconciliation attempts.
Cancellation must terminate its child processes and stop subsequent Git/API work.
Supply credentials only to the short-lived process environment or a bounded
credential helper; never embed them in URLs, Git remotes, command arguments,
configuration files, reports, or diagnostic output. Disable interactive prompts.
Record aggregate fetch/render/commit/push/readback timings and attempt counts via
the common result adapter, with no content, URLs or credentials in phase metrics.

## Required acceptance before promotion

Use the disposable 100/1,000/5,000-page datasets with five versions per page, plus
a loose-object/history-shape variant. Record publisher revision, Forgejo digest,
storage/resources, request/Git-operation counts, latency, commits and readback.
Compare the same dataset and conditions with REST; do not compare different wikis.

- Fresh publish creates one intended batch commit after any bootstrap operation;
  all encoded links resolve. Test branch selection and filename round trips.
- An identical run performs verified comparison and creates no commit. An
  unchanged commit count by itself is insufficient evidence.
- One-page/10% updates touch exactly the byte-different managed content. Unknown
  pages/files/modes and explicitly protected analyst content remain unchanged.
- Inject a concurrent new non-KB file, managed-page edit, rename and deletion
  before push. Exercise successful bounded recomputation and exhausted conflicts.
- Inject authentication failure, rejected push, disconnect before/after remote
  acceptance, cancellation during fetch/render/push, and cleanup failure. Verify
  truthful outcomes and convergent reruns without duplicate commits.
- Confirm secrets are absent from argv, Git configuration/remotes, workspace
  files and logs; exercise the intended Windows/Linux process cleanup paths.
- Repeat publication and readback after an isolated supported-version upgrade,
  then restore the original disposable snapshot into separate storage.

Only choose a production runtime target after those measured complete passes fit
the actual 45-minute wiki budget with explicit headroom. The current REST results
do not establish that target. Preparing this proposal does not publish, upgrade,
prune, change the sink, or replace the shared ingest contract.
