# Workstream 05 — Redaction & Pipeline Robustness

Read `00-OVERVIEW.md` first. Run last (01–04 merged).
All files below are under `zap-kb/` unless stated otherwise.

Two defects:

- **D10 (silent evidence deletion)**: the Forgejo publish defaults to
  `-forgejo-redact=auth,cookies,headers`, and ANY of those modes blanks
  `Occurrence.Request.RawHeader` / `Response.RawHeader` entirely
  (`internal/entities/redact.go`, `RedactEntities`). Result: the Request /
  Response evidence sections that `render.go` promises ("reviewers see raw
  scanner output in the ticket") never appear on default settings, with no
  hint anything was removed. The same blanking degrades every other sink
  (Obsidian, Confluence, Jira) whenever redaction is on.
- **D11 (`log.Fatalf` mid-pipeline)**: `runForgejoPublish` in
  `cmd/zap-kb/forgejo_sync.go` calls `log.Fatalf` on redaction or export
  errors, killing the whole process even though the function's documented
  contract is "return the number of publish failures" and other sinks may
  still need to run (or have state to persist).

## Why the blanket blanking is fixable

The old comment claims "RawHeader is an unstructured string — we cannot
selectively redact it". That is too pessimistic: an HTTP raw header block IS
line-structured — first line is the request/status line, every other line is
`Name: value`. The file already contains the per-header redaction rules for
the structured list (`redactHeaders`); this workstream applies the same rules
line-by-line to the raw block so credentials are scrubbed but the rest of the
evidence survives.

**Safety invariant (non-negotiable)**: after redaction, the output must never
contain a credential that the equivalent structured-header redaction would
have removed. When a line cannot be parsed, redact it entirely — fail closed.

---

## Task 1 — Line-based raw-header scrubbing (D10)

File: `internal/entities/redact.go`.

### 1a. Add the scrubber

```go
// redactRawHeaderBlock applies the same per-header redaction rules as
// redactHeaders to a raw HTTP header block. Raw blocks are line-structured
// (request/status line, then "Name: value" lines), so selective scrubbing is
// possible after all — the historical blanket-blanking threw away the whole
// evidence block on any redaction mode. Lines that do not parse as a header
// are replaced entirely (fail closed): the -redact guarantee that sensitive
// values are gone outranks evidence fidelity.
func redactRawHeaderBlock(raw string, ro RedactOptions) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		suffix := line[len(trimmed):] // preserve \r
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		colon := strings.Index(trimmed, ":")
		// Start-line (request/status), NOT a header: a header name never contains
		// whitespace before its colon, whereas "GET https://h/p HTTP/1.1" and
		// "HTTP/1.1 200 OK" do (or have no colon at all). Do NOT test merely for
		// the absence of a colon — an absolute-URL request target ("GET
		// https://…") contains one and would be mis-parsed as a header.
		if i == 0 && (colon < 0 || strings.ContainsAny(trimmed[:colon], " \t")) {
			if ro.Domain || ro.Query {
				scrubbed := redactHeaders([]Header{{Name: "_line", Value: trimmed}}, ro)
				lines[i] = scrubbed[0].Value + suffix
			}
			continue
		}
		if colon <= 0 {
			lines[i] = "<redacted: unparsed header line>" + suffix
			continue
		}
		name := trimmed[:colon]
		value := strings.TrimSpace(trimmed[colon+1:])
		scrubbed := redactHeaders([]Header{{Name: name, Value: value}}, ro)
		lines[i] = name + ": " + scrubbed[0].Value + suffix
	}
	return strings.Join(lines, "\n")
}
```

Note it deliberately routes every line through the existing `redactHeaders`
so the two code paths can never drift apart. Do not duplicate the name lists.

### 1b. Use it in `RedactEntities`

In `RedactEntities`, find the two blocks guarded by `if rawHeaderRedact`
(request and response). Replace

```go
e.Occurrences[i].Request.RawHeader = ""
e.Occurrences[i].Request.RawHeaderBytes = 0
```

with

```go
e.Occurrences[i].Request.RawHeader = redactRawHeaderBlock(e.Occurrences[i].Request.RawHeader, ro)
e.Occurrences[i].Request.RawHeaderBytes = len(e.Occurrences[i].Request.RawHeader)
```

and the mirrored Response pair likewise. Update the now-wrong comment above
`rawHeaderRedact :=` (the "we cannot selectively redact it" paragraph) to
describe the new behavior — keep the variable, it still gates whether any
scrub runs. `RawHeaderBytes` now means "bytes of the (possibly scrubbed)
block"; note that in the comment.

### 1c. Existing-test fallout

Run `go test ./...`. Tests that asserted `RawHeader == ""` after redaction
will fail — that assertion encoded the old blanking. For each failure:

1. Confirm the test's intent was "credential not present", not
   "field empty".
2. Rewrite the assertion to: output does NOT contain the original secret
   value (e.g. the `Authorization` token string), AND does contain
   `<redacted>` on that header's line.

Never delete a failing assertion without replacing it with the
not-contains-secret form. Likely locations: `internal/entities/` tests,
`internal/output/obsidian/` and `internal/output/confluence/` golden tests,
`internal/e2e/forgejo/redaction_test.go` (the e2e suite explicitly probes
redaction — read that file before changing anything in it; its assertions are
already in not-contains-secret form and should pass unchanged or need only
expectation updates from "section absent" to "section present but scrubbed").

## Task 2 — Stop killing the process (D11)

File: `cmd/zap-kb/forgejo_sync.go`, function `runForgejoPublish`.

Two `log.Fatalf` sites; both become log-and-return (the function already
returns a failure count that callers propagate to the exit code):

1. Redaction failure:

```go
cp, err := redactedCopy(*ent, ro)
if err != nil {
	log.Printf("error: forgejo redaction failed — aborting Forgejo publish so unredacted data is never pushed: %v", err)
	return failures + 1
}
```

2. Export failure:

```go
sum, err := forgejo.Export(exCtx, pubEnt, forgejo.Options{ ... })
if err != nil {
	log.Printf("error: forgejo export: %v", err)
	return failures + 1
}
```

Rationale to preserve in behavior (no code beyond the above): if redaction
fails we must not fall through to publishing — the unredacted copy would leak;
if export fails wholesale (auth/connectivity), the pull and wiki steps would
fail the same way, so returning early avoids noise while the non-zero count
still fails CI.

Then verify (do not change) the callers: `grep -n "runForgejoPublish" cmd/zap-kb/main.go`
— confirm the return value feeds the process exit status (per the function's
doc comment). If a caller *discards* the return value, report that in your
final summary instead of fixing it.

## Tests (required)

File: `internal/entities/redact_test.go` (create if absent; check
`ls internal/entities/*_test.go` first and extend the existing file if one
covers redaction):

1. `TestRedactRawHeaderBlock_ScrubsSensitiveKeepsRest` — input block:

   ```
   GET /search?q=secret HTTP/1.1
   Host: target.example
   Authorization: Bearer sekrit-token
   Cookie: session=abc123
   X-Api-Key: key-456
   Accept: text/html
   ```

   With `RedactOptions{Auth: true, Cookies: true, Headers: true}` assert:
   output does not contain `sekrit-token`, `abc123`, or `key-456`; DOES still
   contain `GET /search?q=secret HTTP/1.1` (query mode off), `Host:
   target.example`, and `Accept: text/html`; the Authorization/Cookie/X-Api-Key
   lines read `<name>: <redacted>`.
2. `TestRedactRawHeaderBlock_QueryAndDomain` — query/domain redaction of the
   request line only fires when the target is an ABSOLUTE URL (`redactURL`
   ignores relative paths, exactly as the structured `_line` rule does — do not
   "fix" this divergently). Use a block whose first line is
   `GET https://target.example/search?q=secret HTTP/1.1` plus a
   `Host: target.example` line; with `RedactOptions{Domain: true, Query: true}`
   assert the output contains neither `secret` nor `target.example`, and keeps
   `Accept: text/html`.
3. `TestRedactRawHeaderBlock_UnparsedLineFailsClosed` — a middle line with no
   colon (`garbage continuation`) becomes `<redacted: unparsed header line>`.
4. `TestRedactEntities_RawHeaderSurvivesScrubbed` — full `EntitiesFile` with
   one occurrence carrying Request+Response raw headers incl. an
   Authorization line; after `RedactEntities` with auth+cookies+headers,
   `RawHeader != ""`, secret absent, `RawHeaderBytes == len(RawHeader)`.

File: `cmd/zap-kb/forgejo_sync_test.go`:

5. `TestRunForgejoPublish_ExportErrorReturnsFailure` — point options at a stub
   server that answers every request with HTTP 400 (Export then fails fast on
   the label/index calls). Assert `runForgejoPublish` RETURNS (process not
   killed) with a value ≥ 1. Keep the entities input minimal (one
   high-risk finding). If constructing this is blocked by unexported
   dependencies, an acceptable fallback is a test that calls the function with
   an unreachable `BaseURL` (e.g. `http://127.0.0.1:1`) and short Timeout —
   the point is only that it returns instead of exiting.

## Acceptance checklist

- [ ] `redactRawHeaderBlock` exists, routes lines through `redactHeaders`, fails closed on unparseable lines.
- [ ] `RedactEntities` scrubs instead of blanking; comments updated; `RawHeaderBytes` recomputed.
- [ ] All pre-existing redaction tests updated to not-contains-secret form — none deleted.
- [ ] No `log.Fatalf` remains in `cmd/zap-kb/forgejo_sync.go` (`grep -n "log.Fatalf" cmd/zap-kb/forgejo_sync.go` → empty).
- [ ] Tests 1–5 pass; full suite green (`go test ./...`); `gofmt -l .` empty; `go vet ./...` clean.
- [ ] Commit: `git commit -s -m "fix(redact,forgejo): scrub raw headers line-wise instead of blanking; never Fatalf mid-pipeline"`

## Out of scope

The forgejo `render.go` evidence sections need no change — once RawHeader
survives redaction, the existing rendering shows the scrubbed block
automatically. Do not add placeholder text for empty RawHeader (empty now
genuinely means "scanner captured nothing"). Do not touch `redactURL`,
`redactCurlAuthHeaders`, or the structured-header path beyond reusing it.
