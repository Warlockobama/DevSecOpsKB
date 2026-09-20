# 02 — Validate evidence before side effects

Status: ready to assign, subject to the dependencies below.

Model: **GPT-5.6 Sol / High** (`gpt-5.6-sol`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G3. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

The baseline accepted {}, an unsupported schemaVersion v999, and a finding whose definition does not exist. Each exited successfully through -entities-in.

Model rationale: The implementation is contained, but backwards compatibility and consistent handling of both import formats require careful reasoning.

## Dependencies and ownership

01 before CLI wiring merges. Package validation and fixtures can start earlier. Give the accepted artifact contract to 03, 05, and 07.

Starting paths: `internal/entities/`, `internal/output/runartifact/runartifact.go`, `internal/output/jsondump/read.go`, `cmd/zap-kb/main.go`, and `docs/schema/entities-v1.md`.

## Assigned work

- Define one shared validation result and supported compatibility matrix for bare entities and run wrappers. Validate versions, collection types, IDs and uniqueness, references, relevant timestamps, and wrapper/entity consistency.
- Distinguish valid zero-finding scans and definitions-only initialization from missing or malformed documents. Specify additive-field and documented legacy normalization policy.
- Validate before persistent replacement, publishable rendering, or destination contact. Do not repair dangling references or silently reinterpret unknown schema versions.
- Preserve native ZAP and representative Cactus/firing-range artifacts, including detection-trace.v1 and established risk/header normalization. Use synthetic portable fixtures.

## Acceptance evidence

- The three baseline invalid documents fail with location-specific, sanitized diagnostics. Both import flags are exercised; no destination writes occur and a preexisting output remains byte-identical.
- Truncated JSON, trailing documents, duplicate IDs, wrong collection types, version mismatch, and dangling references have deterministic failure behavior.
- Valid empty scans, definitions-only input, supported legacy examples, native ZAP data, and representative producer wrappers pass.
- Tests verify side-effect absence, not just an error from a private helper. Record the compatibility matrix with the implementation.

## Escalation and handoff

Ask Astra High to review any proposed identity/schema migration or rejection of a documented producer format. Preserve a failing compatibility fixture instead of weakening validation to make it pass.

Deliver validation entry points and placement, supported/normalized/rejected input matrix, portable fixtures, and any intentional compatibility changes. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
