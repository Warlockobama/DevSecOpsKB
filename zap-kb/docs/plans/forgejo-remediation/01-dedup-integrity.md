# Workstream 01 — Dedup & Rendering Integrity

Read `00-OVERVIEW.md` first (ground rules, build commands).
All files below are under `zap-kb/` unless stated otherwise.

This workstream fixes four defects, all inside `internal/output/forgejo/`:

- **D1 (security)**: the dedup marker is extracted with `strings.Index` (first
  match) while the genuine marker is appended *last* in the issue body. Scanner
  evidence — content controlled by the *scanned website* — is rendered before
  it, so a hostile site can inject a forged marker and poison the dedup index.
- **D2**: evidence containing triple backticks escapes its code fence —
  site-controlled markdown injection into the issue body.
- **D3**: pagination loops stop when a page returns fewer than 50 items. If the
  server's `MAX_RESPONSE_ITEMS` is below 50, every "full" page has fewer than
  50 items, the loop exits after page 1, the dedup index goes blind, and every
  finding is duplicated on every run.
- **D4**: `truncate` and `issueTitle` slice strings by byte index and can split
  a multi-byte UTF-8 character, producing invalid UTF-8 in titles/bodies.

---

## Task 1 — Extract the LAST marker (D1)

File: `internal/output/forgejo/issues.go`, function `markerFindingID`.

Current implementation uses `strings.Index(body, open)`. Replace the function
body so it finds the **last** complete marker in the body:

```go
// markerFindingID extracts the findingID from a body's hidden marker, or "".
// The LAST marker wins: the sink appends the genuine marker at the very end of
// every body it writes, after the Evidence section. Evidence is content
// controlled by the scanned site, so an earlier (forged) marker embedded in a
// response snippet must never shadow the real one.
func markerFindingID(body string) string {
	const open = "<!-- devsecopskb-finding:"
	const closeTok = "-->"
	idx := strings.LastIndex(body, open)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(open):]
	end := strings.Index(rest, closeTok)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}
```

Note the only mechanical change is `Index` → `LastIndex`; the doc comment is
new and required.

## Task 2 — Neutralize marker syntax inside rendered evidence (D1, defense in depth)

File: `internal/output/forgejo/render.go`.

Add this helper near `truncate`:

```go
// sanitizeUntrusted neutralizes HTML-comment openers in site-controlled text
// so a scanned target can never smuggle a forged dedup marker (or any HTML
// comment) into an issue body. Breaking "<!--" into "<!- -" destroys comment
// syntax while keeping the snippet readable.
func sanitizeUntrusted(s string) string {
	return strings.ReplaceAll(s, "<!--", "<!- -")
}
```

Then in `evidenceMarkdown`, wrap every piece of occurrence-derived text with
`sanitizeUntrusted(...)`. The occurrence fields rendered there are `occ.Param`,
`occ.Attack`, `occ.Evidence`, `occ.Request.RawHeader`, `occ.Response.RawHeader`.
Example for the evidence snippet line — current code:

```go
fmt.Fprintf(&b, "```\n%s\n```\n", truncate(e, 1000))
```

becomes (fence change comes from Task 3; apply both):

```go
writeFencedBlock(&b, "", sanitizeUntrusted(truncate(e, 1000)))
```

Also wrap in `buildIssueBody` (same file): `f.URL` is scanner-derived; wrap it
with `sanitizeUntrusted` too. And in `issueTitle`, apply `sanitizeUntrusted`
to `name` before the length check.

## Task 3 — Fence-safe code blocks (D2)

File: `internal/output/forgejo/render.go`.

Add this helper:

```go
// writeFencedBlock writes content as a fenced code block whose fence is longer
// than any backtick run inside the content, so site-controlled snippets can
// never terminate the fence early and inject markdown into the issue body
// (CommonMark: a fence only closes on a run at least as long as the opener).
func writeFencedBlock(b *strings.Builder, lang, content string) {
	fenceLen := 3
	run := 0
	for _, r := range content {
		if r == '`' {
			run++
			if run >= fenceLen {
				fenceLen = run + 1
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", fenceLen)
	b.WriteString("\n")
	b.WriteString(fence)
	b.WriteString(lang)
	b.WriteString("\n")
	b.WriteString(content)
	b.WriteString("\n")
	b.WriteString(fence)
	b.WriteString("\n")
}
```

In `evidenceMarkdown`, replace the three `fmt.Fprintf(&b, "```...")` fenced
blocks with `writeFencedBlock`:

- Evidence snippet → `writeFencedBlock(&b, "", sanitizeUntrusted(truncate(e, 1000)))`
  (keep the preceding `**Evidence snippet:**` heading line; the helper adds the
  surrounding blank lines, so drop any now-duplicated `\n` writes — render the
  output of a test to check spacing).
- Request → `writeFencedBlock(&b, "http", sanitizeUntrusted(truncate(occ.Request.RawHeader, 2000)))`
- Response → `writeFencedBlock(&b, "http", sanitizeUntrusted(truncate(occ.Response.RawHeader, 2000)))`

For the inline-code spans (`occ.Param`, `occ.Attack` rendered inside single
backticks): if the sanitized value contains a backtick, fall back to no code
formatting rather than building variable-length inline spans. Add:

```go
// inlineCode renders s as inline code, or plain text when s itself contains a
// backtick (which would terminate the span early).
func inlineCode(s string) string {
	if strings.Contains(s, "`") {
		return s
	}
	return "`" + s + "`"
}
```

and use `inlineCode(sanitizeUntrusted(p))` / `inlineCode(sanitizeUntrusted(truncate(a, 300)))`
in the Parameter/Attack lines.

## Task 4 — Pagination must run until an empty page (D3)

Three paginated list loops share the same bug — they break on
`len(batch) < 50`:

1. `internal/output/forgejo/issues.go`, function `listFindingIssues`
2. `internal/output/forgejo/labels.go`, function `listLabels`
3. `internal/output/forgejo/wiki.go`, function `listWikiPages`

In each, replace the `if len(batch) < 50 { break }` (or `return out, nil`)
termination with:

```go
if len(batch) == 0 {
	break // past the last page; never trust page size — servers cap `limit`
}
page++
if page > 1000 {
	return nil, fmt.Errorf("forgejo: pagination exceeded 1000 pages — aborting (server ignoring page param?)")
}
```

Adjust per-function: `listWikiPages` returns `(map[string]string, error)` and
currently `return out, nil` on the short page — keep returning `out, nil` after
the loop ends via `break`. Keep the existing 404 early-return in
`listWikiPages` untouched. The `limit=50` query parameter stays as-is (it is a
hint, not a contract).

Note this costs exactly one extra request per listing (the final empty page).
That is acceptable; do not try to optimize it away.

## Task 5 — Rune-safe truncation (D4)

File: `internal/output/forgejo/render.go`.

Replace `truncate` with:

```go
// truncate shortens s to at most n bytes without splitting a UTF-8 sequence,
// appending an ellipsis when anything was cut.
func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
```

Add `"unicode/utf8"` to the imports.

In `issueTitle`, replace the manual `name[:252] + "..."` block with:

```go
if len(name) > 255 {
	name = truncate(name, 252)
}
```

## Tests (required, all in `internal/output/forgejo/`)

Add to `forgejo_test.go` (or a new `render_integrity_test.go` in the same
package). Test names and the behavior each must assert:

1. `TestMarkerFindingID_LastMarkerWins` — body containing
   `"<!-- devsecopskb-finding:forged -->\nstuff\n<!-- devsecopskb-finding:real -->"`
   returns `"real"`.
2. `TestBuildIssueBody_ForgedMarkerInEvidenceNeutralized` — build a finding
   with FindingID `"real"` and an occurrence whose `Evidence` field is
   `"<!-- devsecopskb-finding:forged -->"`. Assert
   `markerFindingID(buildIssueBody(f, nil, occ)) == "real"` **and** the body
   does not contain the literal substring `"<!-- devsecopskb-finding:forged"`.
3. `TestEvidenceMarkdown_BackticksCannotEscapeFence` — occurrence with
   `Evidence: "x\n```\n# injected heading\n```\ny"`. Assert the rendered
   evidence block's opening fence is at least 4 backticks and that the string
   `"\n# injected heading"` only ever appears between the opening and closing
   fence (simplest robust assertion: the longest backtick run in the output is
   the fence itself and it is strictly longer than any run in the input).
4. `TestListFindingIssues_ServerCapsPageSize` — stub server that ignores
   `limit=50` and returns at most 3 issues per page across 7 total issues
   (each with a distinct marker body), empty array past the last page. Assert
   all 7 findings appear in the returned map. Model the stub on the existing
   stub-server tests in `forgejo_test.go`.
5. `TestTruncate_RuneSafe` — `truncate("héllo", 2)` must return a valid UTF-8
   string (`utf8.ValidString`) that does not contain a broken `é`; also
   `truncate("abc", 3) == "abc"` (no ellipsis when nothing cut).
6. `TestIssueTitle_LongMultibyteTitle` — a 300-rune title of `"é"` repeated;
   result must be ≤255 bytes, valid UTF-8, ending in `"…"`.

Existing tests will exercise the changed fences — if an existing test asserts
an exact rendered body containing three-backtick fences, update its expectation
to match the new output (verify the new output is correct first, then update).

## Acceptance checklist

- [ ] `markerFindingID` uses `LastIndex`; doc comment explains why.
- [ ] All occurrence-derived text in `render.go` passes through `sanitizeUntrusted`.
- [ ] All fenced blocks use `writeFencedBlock`; inline spans use `inlineCode`.
- [ ] All three list loops terminate only on an empty page (with the 1000-page guard).
- [ ] `truncate` is rune-safe; `issueTitle` uses it.
- [ ] The 6 new tests above exist and pass.
- [ ] `go build ./... && go test ./... && go vet ./...` green; `gofmt -l .` empty.
- [ ] Commit: `git commit -s -m "fix(forgejo): harden dedup marker, fences, pagination against hostile/short input"`

## Out of scope

Do not touch reopen logic, labels semantics, pull.go, wiki link rewriting, or
redaction — later workstreams own those.
