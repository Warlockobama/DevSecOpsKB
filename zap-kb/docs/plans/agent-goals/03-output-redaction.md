# 03 — Apply redaction across every emitted representation

Status: ready to assign, subject to the dependencies below.

Model: **GPT-6 Astra / High** (`gpt-6-astra`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G2. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

With -redact query,cookies,auth, the baseline entities scrubbed a synthetic cookie while run.json raw alerts retained it. Preview output also retained a query marker.

Model rationale: This change spans raw and normalized evidence, serialization, logs, archives, and external payloads. Missing one path can defeat the user's requested protection.

## Dependencies and ownership

02 before artifact-boundary integration. Coordinate the sanitized diagnostic policy with 04; 06 consumes it.

Starting paths: `internal/entities/redact.go`, `internal/output/runartifact/`, `internal/output/ziputil/`, artifact/preview code in `cmd/zap-kb/main.go`, and `cmd/zap-kb/forgejo_sync.go`.

## Assigned work

- Trace the actual emitted representations and define a single output policy for entities, raw alerts, metadata, previews/errors, Markdown, sink payloads, and ZIP members.
- Derive output views from internal evidence while preserving finding/occurrence identity and useful nonsensitive context. Preserve the existing protective Forgejo defaults when additional modes are supplied.
- Make raw-evidence retention explicit and document any changed defaults. A retention option must not silently override requested redaction for shared output.
- Reject unknown modes. Map every supported mode to the representations it protects, including notes/headers/body/metadata where applicable. Apply sanitization on failure paths as well as successful output.

## Acceptance evidence

- Reproduce the baseline cookie/query leaks in tracked CLI tests and prove they are absent after the fix.
- Place unique synthetic markers in cookies, auth, query, body, headers, notes, and metadata. Search every applicable output, stdout/stderr, archive member, and mock-captured destination payload for leakage under its requested mode.
- Verify stable IDs and scan/source labels, useful nonsensitive evidence, unchanged source input, and the existing Forgejo redaction/ownership regressions.
- Exercise failures containing sensitive server/input context. Capture only sanitized diagnostic results.

## Escalation and handoff

Use Astra XHigh only for a specific unresolved identity-versus-redaction or compatibility decision after constructing a minimal reproducer. Do not raise effort merely because the test matrix is large.

Deliver an output-policy matrix, raw-retention compatibility decision, end-to-end leak tests, and the sanitization contract consumed by 04. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
