# Triage Policy (`triage-policy.yaml`)

`triage-policy.yaml` holds the operator-tunable knobs that govern automated
triage decisions in the merge pipeline and exporters. It is the **single
source of truth** for these values — there are deliberately no CLI flags
that shadow them, so behavior travels with the vault and analysts get a
consistent view across runs.

Epic #71 (analyst lifecycle) introduced this file so behaviors like
auto-reopen, auto-suppression, and rule tuning thresholds can be adjusted
per-org without recompiling.

## Resolution order

`zap-kb` looks for the file in this order and stops at the first hit:

1. `./triage-policy.yaml` in the current working directory (typically the
   project / vault root). **This wins** — checked-in YAML is authoritative
   over a per-machine override.
2. `<user-config-home>/devsecopskb/triage-policy.yaml`
   (e.g. `~/.config/devsecopskb/triage-policy.yaml` on Linux,
   `%APPDATA%\devsecopskb\triage-policy.yaml` on Windows).
3. Built-in defaults (see `internal/config/policy.go:DefaultPolicy()`).

Partial files are safe: any field omitted from the YAML keeps its built-in
default rather than being zero-valued. So a one-field override file does
not silently disable everything else.

## Subcommands

```bash
# Print the resolved policy and where it came from (JSON, pipe-friendly).
zap-kb config show

# Write a heavily commented default file at ./triage-policy.yaml.
# Refuses to overwrite an existing file — delete it first if you mean to.
zap-kb config init
zap-kb config init -path /custom/location/triage-policy.yaml
```

## Fields

| Field | Type | Default | Effect |
|---|---|---|---|
| `autoReopenOnRecurrence` | bool | `true` | When `Merge()` sees new occurrences for a finding whose status is `fp` or `fixed`, transition status back to `open`, stash `priorStatus`, and append an audit entry. (Epic #71 slice 1b / issue #57.) Set `false` to restore pre-slice-1b behavior where `Recurrence` is advisory only. |
| `findingFPSuppressionThreshold` | int | `3` | After this many distinct false-positive history entries on a single finding, the pipeline writes an auto-`Suppression` so the finding stops appearing in triage queues. `<=0` disables. (Epic #71 slice 1c-ii.) |
| `findingFPSuppressionExpiryDays` | int | `90` | Days an auto-`Suppression` lasts before it expires and the finding returns to triage for re-confirmation. Prevents permanent hide-and-forget on findings whose context may have changed. |
| `ruleTuneScanThreshold` | int | `5` | Aggregate fp count across all findings sharing a `pluginId`. When the total reaches this threshold, the matching `Definition` is tagged `tune-scan` so security engineering can prioritize tuning the detection rule. `<=0` disables. (Epic #71 slice 1c-ii.) |
| `acceptedDefaultExpiryDays` | int | `180` | Default `acceptedUntil` window applied when an analyst marks a finding `accepted` without supplying their own `acceptedUntil` date. (Epic #71 slice 2 / issue #58 — acceptance-expired report.) |

## Example

```yaml
# triage-policy.yaml — minimal override; all other fields keep defaults.
autoReopenOnRecurrence: true
findingFPSuppressionThreshold: 5
ruleTuneScanThreshold: 10
```

## Why YAML and not flags

These are **policy** decisions (security-team scope), not engineering
knobs. Putting them in CLI flags invites per-invocation drift — one
analyst runs with `-fp-threshold=2`, another with `-fp-threshold=10`, and
the auto-suppression behavior becomes non-reproducible. Keeping them in a
checked-in YAML file means the policy is reviewable, version-controlled,
and consistent across every run that touches the same vault.
