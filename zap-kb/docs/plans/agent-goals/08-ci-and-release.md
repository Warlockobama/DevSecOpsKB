# 08 — Make CI coverage and deployed build identity explicit

Status: ready to assign, subject to the dependencies below.

Model: **GPT-5.6 Terra / High** (`gpt-5.6-terra`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G7 CI, documentation wiring, and release provenance. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

The assessment found obsolete e2e paths in build/workflow configuration. The live publishers used an August 9-tagged image whose current-main revision was not verified. Current source tests cannot prove the behavior of that deployed binary.

Model rationale: Build paths, test execution and image metadata are concrete and verifiable. A production migration or new deployment architecture is outside this bounded assignment.

## Dependencies and ownership

Existing CI path repair can start immediately. Final acceptance wiring follows 01–07 and 09. 06 owns the disposable Forgejo upgrade/performance experiment.

Starting paths: Repository root `.github/workflows/`; module `Makefile`, `Dockerfile`, `deploy/Dockerfile`, `docker/`, build/version metadata and release docs. Supply companion manifest recommendations to 07/10 rather than independently editing that checkout.

## Assigned work

- Inventory actual Go, tagged integration, and browser e2e suites and their prerequisites. Repair stale paths and make the event-to-suite mapping explicit without silently skipping a broken test.
- Wire the CLI contract tests delivered by 01–05 into the appropriate required build path. Integrate the benchmark/smoke commands from 06 in an explicitly bounded workflow.
- Record source revision in built binaries/images and pin deployment references reproducibly. Provide a way to compare a running digest/revision with the reviewed source.
- Update relevant build/release docs and links using verified commands. Prepare exact build/test/release steps and rollback references.
- Validate locally and through available non-publishing checks. Do not push an image, trigger a production rollout, or change protected-branch settings simply to finish CI wiring.

## Acceptance evidence

- Every documented suite path exists; available commands execute the intended suite and failures propagate. Service-dependent suites clearly name their prerequisites.
- Relevant workflow syntax and build commands validate. Report which hosted CI checks actually ran versus were only inspected locally.
- A local built artifact exposes the expected source revision. Release instructions produce an immutable image reference and explain how to verify it.
- The final matrix includes all delivered regression suites, with unavailable service acceptance stated rather than omitted.

## Escalation and handoff

Escalate to Sol High if versioning/release design affects multiple deployment systems or CI failures remain unexplained after a focused reproduction. Give 06 upgrade-performance decisions rather than making them here.

Deliver cI suite/event map, repaired commands, source/digest verification, local validation, and a concrete release procedure. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
