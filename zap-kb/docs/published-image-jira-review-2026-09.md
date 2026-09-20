# Published image Jira Cloud review

Observed 12 September 2026 local time (13 September UTC), following the owner's report that a workplace pipeline uses the GitHub `latest` image and Jira issues were not created. The exact image pulled during that earlier run and its logs are unavailable.

## Image identity

The repository's publication workflow names `ghcr.io/warlockobama/zap-kb-atlassian:latest` and builds `zap-kb/deploy/Dockerfile`. This is the minimal publisher image, distinct from the full ZAP runtime image.

The current tag resolved to index digest `sha256:465736677d25682c8be936d7521478636d6728c63266187e6b977a9646b7da24`. Tests used that immutable reference. Its amd64 image reports creation at `2026-08-06T16:53:49Z`, entrypoint `zap-kb`, default argument `-h`, and user `65532:65532`. Its config has no source revision label, and the extracted binary's Go build information has no VCS revision. The date is not a substitute for an identified source commit.

## Controlled container results

The actual image ran in an isolated Docker network with synthetic scan input, synthetic environment credentials, and a local HTTP service emulating selected Jira API responses. The network had no external route. This tests URL selection, request shape, outcomes, and artifact retention; it does not test Atlassian authentication, real project permissions, or tenant field configuration.

| Case | Observed requests and result | Process exit |
|---|---|---|
| Normal Cloud site URL, accepted create | REST v3 enhanced search, then REST v3 issue create; project `TEST`, issue type `Bug`, ADF description; summary created=1/errors=0 | 0 |
| Normal Cloud site URL, rejected create | REST v3 issue create receives synthetic HTTP 400; summary created=0/errors=1 | **0, incorrectly successful** |
| Scoped-token gateway URL, auto deployment | `api.atlassian.com/ex/jira/mock-cloud` is classified as Data Center and calls REST v2 search; no Cloud create; summary created=0/errors=1 | **0, incorrectly successful** |

All cases emitted a run artifact. The successful case establishes that the image can send a correctly shaped basic Cloud create request under a controlled accepted response. It does not establish that arbitrary workplace projects accept that payload. The two failure cases establish concrete defects in the currently published image. They are plausible explanations to investigate for the workplace incident, not a proven reconstruction of that incident.

## Required corrected-image acceptance

Assignment 04 owns gateway classification, actionable sanitized Jira diagnostics, safe deduplication/retries, and truthful aggregate outcomes. Assignment 08 owns the normal container build/entrypoint path and source/digest identity. Repeat the three cases above against the corrected `deploy/Dockerfile` image, including create/readback/repeat without duplication, intentional rejection, and retained failure artifacts. Keep original and corrected image digests in the evidence.

No replacement image was pushed and no workplace or production repository was contacted by this probe. A later designated Jira/Confluence tenant must verify authentication, permissions, project/issue-type fields, and actual create/readback. The earlier workplace image remains unidentified because `latest` is mutable and the historic pull digest is unavailable.

Sanitized local evidence: integration worktree `out/goal-pack/published-image-metadata.json`, `published-image-buildinfo.txt`, `published-image-probe.json`, and case-specific request logs. Reproducer: `probe_published_image.py` and `jira_mock.go` in the same ignored directory. Temporary containers and network were removed by the probe's cleanup path.
