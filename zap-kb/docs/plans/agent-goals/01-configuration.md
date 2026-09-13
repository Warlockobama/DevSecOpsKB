# 01 — Make configuration precedence predictable

Status: ready to assign, subject to the dependencies below.

Model: **GPT-5.6 Terra / High** (`gpt-5.6-terra`, reasoning `high`). This is a recommendation; select it in task settings.

Parent coverage: G5. Read [shared execution contract](SHARED.md), [dispatch index](README.md), and the relevant [parent goal](../reliability-goals-2026-09.md).

## Goal and starting evidence

The CLI registers a nonempty localhost ZAP URL default, then applies environment values only to empty strings. ZAP_URL therefore loses to the default. An explicit URL reaches the same controlled endpoint.

Model rationale: The failure is reproduced and the desired precedence is explicit. This is bounded implementation, with escalation if it expands into a general configuration framework.

## Dependencies and ownership

None. Coordinate the resolver interface with 04; 04 owns Jira Cloud/Data Center dialect behavior.

Starting paths: `cmd/zap-kb/main.go`, `cmd/zap-kb/atlassian_config.go`, their tests, and `docker/zap-kb-entrypoint.sh`.

## Assigned work

- Implement explicit flag > environment > default. Track whether each flag was supplied; do not equate false, zero, or a deliberate empty value with an absent flag.
- Inventory existing advertised flag/environment pairs and apply the contract consistently. Define empty-value, whitespace, malformed URL, invalid mode, and disabled-destination behavior. Keep the change to configuration resolution and its call sites.
- Expose configuration sources without exposing credential values. Align container examples and CLI help with the actual behavior.
- Agree with 04 on deployment input handling. Test explicit Cloud selection and gateway inputs against that interface; 04 implements Jira dialect classification. Leave broad orchestration extraction to 09.

## Acceptance evidence

- A subprocess CLI test with only ZAP_URL contacts the intended mock; default-only and explicit-override cases reach their expected endpoints.
- Representative strings, booleans, durations, zero/false values, explicit empty values, and invalid settings behave as documented.
- Secrets never appear in source diagnostics or failure output. Existing Atlassian configuration tests remain compatible.
- Provide a short precedence table and the commands used to check the container entrypoint without publishing.

## Escalation and handoff

Escalate to Sol High if multiple command families need a new configuration architecture. Do not broaden this fix into rendering or sink orchestration changes.

Deliver resolver behavior and interface, before/after ZAP reproduction, the advertised settings covered, and any remaining per-sink dialect work handed to 04. Include the shared handoff fields and distinguish local versus live verification.

## Starter prompt

Read this assignment and its linked shared execution contract. Implement its available scope, respecting the stated dependencies and file ownership. Reproduce the baseline behavior, complete the acceptance evidence, and hand back a reviewable patch with validation and remaining external acceptance. Do not take ownership of the other numbered assignments.
