# Input validation and compatibility

All entities and run-artifact imports pass through the same validation boundary
before zap-kb renders output, replaces a persistent file, or contacts a
destination. `-entities-in` accepts a bare entities document. `-run-in` accepts
either a bare entities document or a `zap-kb/run/v1` wrapper. Package consumers
use `runartifact.ReadEntities`, `runartifact.Read`, or
`runartifact.ReadValidated`/`ReadFlexible` for the same checks.

Validation errors identify a JSON field path and a problem category. They do
not include the rejected value, URL, evidence, note, or header. A document that
has either wrapper discriminator (`schema` or `entities`) remains a wrapper for
validation; an invalid wrapper is never retried as bare entities.

## Compatibility matrix

| Input | Handling | Compatibility notes |
| --- | --- | --- |
| Bare entities with `schemaVersion: "v1"` and declared `definitions`, `findings`, and `occurrences` arrays | Supported | Any collection may be empty. A declared empty scan and definitions-only initialization are valid. `generatedAt` and `sourceTool` are retained, including when every collection is empty. |
| `zap-kb/run/v1` wrapper with `meta` and v1 `entities` | Supported | Wrapper/entity `sourceTool` and `generatedAt` must agree when both copies are present. Optional `alerts`, when present, must be an array. |
| Native ZAP alerts supplied through `-in` | Supported | They are converted by the existing builder into a validated v1 entities graph. This is not an entities/run-wrapper import. |
| Cactus Sheriff wrapper | Supported | Custom identities and the JSON-encoded provenance in `occurrences[].other`, including `detection-trace.v1`, are retained. |
| Firing-range/multi-producer wrapper | Supported | The documented external scalar/header conversions below are applied before typed decoding. |
| Historical v1 `null` top-level collections | Normalized | `definitions`, `findings`, and `occurrences` `null` values are converted to empty arrays. New zap-kb output writes empty arrays. |
| String `definition.wascid` containing an integer | Normalized | Converted to a JSON number. An empty string is treated as the omitted optional value. |
| Numeric `finding.riskcode` or `occurrence.riskcode` | Normalized | Converted to its string form. |
| Request/response `headers` as an array of `"Name: value"` lines | Normalized | Converted to `{ "name": ..., "value": ... }` objects. |
| Additive unknown object fields | Accepted for forward-compatible reading | zap-kb does not interpret unmodeled fields and does not promise to reproduce them when it rewrites the document. Producer evidence that must survive a round trip belongs in a modeled field such as `occurrences[].other`. |
| Missing/unsupported schema version, missing collections, object/scalar collection values, truncated JSON, or trailing JSON values | Rejected | No fallback or version coercion is performed. |
| Empty, duplicate, whitespace-padded, or path-unsafe IDs; dangling/inconsistent references; mismatched finding/definition plugin IDs | Rejected | zap-kb does not repair identities or invent referenced records. Every graph ID, graph reference, and `pluginId` must be one portable path component: `/`, `\\`, Windows filename metacharacters (`< > : " | ? *`), control characters, `.`/`..`, and Windows device names are rejected. Other punctuation, internal spaces, and Unicode text remain supported. |
| Invalid RFC3339 timestamps or reversed finding first/last ranges | Rejected | Diagnostics name the timestamp path without copying its value. |

Successful validation returns a `runartifact.ValidationResult`. Its format and
schema fields describe the accepted input, and its `Normalizations` entries
record the path and rule for every compatibility conversion without retaining
the original value.

## Graph checks

- Definition, finding, occurrence, and analyst-history entry IDs are nonempty
  and unique in their collection.
- Graph IDs, references, and plugin IDs are portable single path components so
  renderer filenames cannot escape or alias their intended directory.
- Every finding references an existing definition and uses the same `pluginId`.
- Every occurrence references an existing finding and definition, and the two
  references agree.
- An occurrence-scoped suppression references an occurrence owned by that
  finding.
- Present timestamps use RFC3339. Empty optional timestamp fields remain
  supported for existing v1 data.

The validator does not recompute deterministic IDs, occurrence counts, risk,
or analyst decisions. Those values retain their existing schema meaning and
ownership.

The additive `exportPolicy` string is modeled and retained in typed artifacts. Merge retains a policy only when both inputs agree; mixed or unstamped inputs clear the claim. Original source artifacts are separate from publication state; see [publication state](../publication-state.md).
