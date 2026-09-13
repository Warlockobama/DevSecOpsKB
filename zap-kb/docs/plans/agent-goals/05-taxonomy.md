# 05 — Connect curated taxonomy without changing identity

Status: ready to assign, subject to the dependencies below.

Model: **GPT-5.6 Sol / High** (`gpt-5.6-sol`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G4. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

A definition matching zap-authenticated-basket-item-enumeration leaves the CLI without the curated taxonomy, although the helper test expects CWE 639. EnrichCustomTaxonomy has no production call. PR #94 was open and conflicted at the baseline; refresh its status before reuse.

Model rationale: The missing production call is concrete. The difficult part is mapping semantics and precedence, so unsupported classifications or identity changes escalate for stronger review.

## Dependencies and ownership

02 and 03 before pipeline integration. Mapping research and PR #94 review can start earlier.

Starting paths: `internal/entities/enrich.go`, `internal/entities/taxonomy.go`, `internal/zapmeta/custom_taxonomy.go`, `internal/zapmeta/zapmeta.go`, CLI enrichment placement, and taxonomy output tests.

## Assigned work

- Inspect the current diff and state of https://github.com/Warlockobama/DevSecOpsKB/pull/94. Reconcile relevant work into the assignment patch; do not blindly merge or publish the old PR.
- Place enrichment consistently in the validated pipeline and document precedence among native scanner values, curated mappings, reviewed analyst/advisory values, and derived labels.
- Review changed mappings against detection semantics and authoritative taxonomy sources. Preserve attribution/confidence and leave unmapped rules explicitly incomplete.
- Support current lookup aliases without changing stored definition/finding IDs or creating duplicate issues. Preserve analyst fields and detection traces.

## Acceptance evidence

- The exact failing rule gets the justified taxonomy through the CLI into entities, run artifacts, and rendered output.
- Fixtures cover source-prefixed aliases, unmapped rules, numeric native ZAP rules, previously reviewed taxonomy, and repeated imports.
- IDs and native/custom separation remain stable; repeat imports do not create duplicate definitions or finding identities.
- Each changed mapping has traceable evidence; a helper test or successful compile alone is insufficient.

## Escalation and handoff

Escalate to Astra High if a mapping is semantically disputed, precedence would overwrite reviewed data, or a migration is needed. Keep uncertain mappings unresolved rather than inventing a classification.

Deliver pR reconciliation notes, enrichment order, mapping evidence, and CLI identity/round-trip results. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
