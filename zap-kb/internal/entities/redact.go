package entities

import (
	neturl "net/url"
	"path"
	"regexp"
	"strings"
)

// RedactOptions controls redaction.
// Supported keys (case-insensitive):
//
//	domain   - replace host with <redacted>
//	query    - zero out query parameter values
//	cookies  - redact Cookie and Set-Cookie headers
//	auth     - redact Authorization header value
//	headers  - redact sensitive headers (X-Api-Key, Api-Key, X-Auth-Token)
//	body     - drop BodySnippet values (keep byte counts)
//	notes    - zero analyst-authored free text (Analyst.Notes, Analyst.Rationale)
//	           and scanner-supplied reproduction steps (Reproduce.Steps[]) that
//	           can inadvertently carry pasted credentials or PII.
//	secrets  - scrub credential/PII patterns (password hashes, emails, JWTs)
//	           OUT OF the free-text scanner evidence (Occurrence.Evidence,
//	           Attack, Name, Reproduce.Curl) while leaving the rest of the
//	           snippet intact — unlike body, which drops the whole field. Keeps
//	           captured secrets off a shared KB without gutting actionable
//	           evidence (e.g. "SQLITE_ERROR: incomplete input" survives).
type RedactOptions struct {
	Domain  bool
	Query   bool
	Cookies bool
	Auth    bool
	Headers bool
	Body    bool
	Notes   bool
	Secrets bool
}

var (
	// reSecretEmail matches email addresses captured in evidence (PII).
	reSecretEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	// reSecretJWT matches a JWT (header.payload.signature, base64url) — these
	// carry session/identity material and, in Juice Shop's case, a password hash.
	reSecretJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]+`)
	// reSecretHash matches a contiguous hex run the length of a common digest
	// (MD5/SHA-1/SHA-256/…), i.e. a captured password/credential hash. Bounded
	// by \b so occurrence IDs and short scan tokens are not caught.
	reSecretHash = regexp.MustCompile(`\b[a-fA-F0-9]{32,128}\b`)
)

// redactSecretsText scrubs credential/PII patterns from a free-text scanner
// string, replacing each match with a labeled placeholder. JWT is scrubbed
// before the hash rule so its base64url segments are not partially masked.
func redactSecretsText(s string) string {
	if s == "" {
		return s
	}
	s = reSecretJWT.ReplaceAllString(s, "<redacted-token>")
	s = reSecretEmail.ReplaceAllString(s, "<redacted-email>")
	s = reSecretHash.ReplaceAllString(s, "<redacted-hash>")
	return s
}

func ParseRedactOptionList(list string) RedactOptions {
	ro := RedactOptions{}
	for _, f := range strings.FieldsFunc(strings.ToLower(list), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		switch strings.TrimSpace(f) {
		case "domain":
			ro.Domain = true
		case "query":
			ro.Query = true
		case "cookies", "cookie":
			ro.Cookies = true
		case "auth", "authorization":
			ro.Auth = true
		case "headers", "header":
			ro.Headers = true
		case "body":
			ro.Body = true
		case "notes", "note":
			ro.Notes = true
		case "secrets", "secret", "pii", "credentials":
			ro.Secrets = true
		}
	}
	return ro
}

func RedactEntities(e *EntitiesFile, ro RedactOptions) {
	if e == nil {
		return
	}
	for i := range e.Findings {
		if ro.Notes && e.Findings[i].Analyst != nil {
			e.Findings[i].Analyst.Notes = ""
			e.Findings[i].Analyst.Rationale = ""
		}
		if ro.Secrets {
			e.Findings[i].Name = redactSecretsText(e.Findings[i].Name)
		}
		if ro.Domain || ro.Query {
			e.Findings[i].URL = redactURL(e.Findings[i].URL, ro)
			// Rebuild Name from the redacted URL so it no longer contains the original host.
			if ro.Domain {
				base, hostRoot := urlBaseOrParent(e.Findings[i].URL)
				name := ""
				if base != "" {
					name = base
				} else if hostRoot != "" {
					name = hostRoot
				}
				if name != "" {
					e.Findings[i].Name = name
				}
			}
		}
	}
	// rawHeaderRedact is true whenever any mode that can expose credentials in the
	// raw header block is active. The raw block is line-structured, so it is
	// scrubbed line-by-line (see redactRawHeaderBlock) rather than blanked — the
	// scrubbed evidence stays useful while sensitive values are removed.
	// RawHeaderBytes is recomputed to the post-scrub length.
	rawHeaderRedact := ro.Cookies || ro.Auth || ro.Headers || ro.Domain || ro.Query

	for i := range e.Occurrences {
		if ro.Notes {
			if e.Occurrences[i].Analyst != nil {
				e.Occurrences[i].Analyst.Notes = ""
				e.Occurrences[i].Analyst.Rationale = ""
			}
			if e.Occurrences[i].Reproduce != nil {
				e.Occurrences[i].Reproduce.Steps = nil
			}
		}
		if ro.Domain || ro.Query {
			e.Occurrences[i].URL = redactURL(e.Occurrences[i].URL, ro)
			// Rebuild Name from the redacted URL so it no longer contains the original host.
			if ro.Domain {
				base, hostRoot := urlBaseOrParent(e.Occurrences[i].URL)
				name := ""
				if base != "" {
					name = base
				} else if hostRoot != "" {
					name = hostRoot
				}
				if name != "" {
					e.Occurrences[i].Name = name
				}
			}
		}
		// body mode: zero scan payload fields that can contain credentials or PII
		if ro.Body {
			e.Occurrences[i].Attack = ""
			e.Occurrences[i].Evidence = ""
			if e.Occurrences[i].Reproduce != nil {
				e.Occurrences[i].Reproduce.Curl = ""
			}
		}
		// secrets mode: surgically scrub credential/PII patterns from the
		// free-text scanner fields, keeping the rest of the evidence usable.
		if ro.Secrets {
			e.Occurrences[i].Evidence = redactSecretsText(e.Occurrences[i].Evidence)
			e.Occurrences[i].Attack = redactSecretsText(e.Occurrences[i].Attack)
			e.Occurrences[i].Name = redactSecretsText(e.Occurrences[i].Name)
			if e.Occurrences[i].Reproduce != nil {
				e.Occurrences[i].Reproduce.Curl = redactSecretsText(e.Occurrences[i].Reproduce.Curl)
			}
		}
		// auth mode: scrub auth headers embedded in Reproduce.Curl
		if ro.Auth && e.Occurrences[i].Reproduce != nil && e.Occurrences[i].Reproduce.Curl != "" {
			e.Occurrences[i].Reproduce.Curl = redactCurlAuthHeaders(e.Occurrences[i].Reproduce.Curl)
		}
		// headers
		if e.Occurrences[i].Request != nil {
			if ro.Body {
				e.Occurrences[i].Request.BodySnippet = ""
			}
			if rawHeaderRedact {
				e.Occurrences[i].Request.Headers = redactHeaders(e.Occurrences[i].Request.Headers, ro)
				e.Occurrences[i].Request.RawHeader = redactRawHeaderBlock(e.Occurrences[i].Request.RawHeader, ro)
				e.Occurrences[i].Request.RawHeaderBytes = len(e.Occurrences[i].Request.RawHeader)
			}
		}
		if e.Occurrences[i].Response != nil {
			if ro.Body {
				e.Occurrences[i].Response.BodySnippet = ""
			}
			if rawHeaderRedact {
				e.Occurrences[i].Response.Headers = redactHeaders(e.Occurrences[i].Response.Headers, ro)
				e.Occurrences[i].Response.RawHeader = redactRawHeaderBlock(e.Occurrences[i].Response.RawHeader, ro)
				e.Occurrences[i].Response.RawHeaderBytes = len(e.Occurrences[i].Response.RawHeader)
			}
		}
	}
}

func redactURL(raw string, ro RedactOptions) string {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return raw
	}
	if ro.Domain && u.Host != "" {
		// preserve TLD-style shape if possible
		u.Host = "<redacted>"
	}
	if ro.Query && u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			q.Set(k, "<redacted>")
		}
		u.RawQuery = q.Encode()
	}
	// Normalize path a bit so redaction feels clean
	if u.Path == "" {
		u.Path = "/"
	} else {
		u.Path = path.Clean(u.Path)
	}
	return u.String()
}

// redactCurlAuthHeaders replaces Authorization and Cookie header values inside a
// curl command string with sentinel tokens, matching the same patterns used in
// buildCurl in the obsidian output package.
func redactCurlAuthHeaders(curl string) string {
	// Replace -H "Authorization: <anything>" patterns.
	curl = redactCurlHeader(curl, "Authorization", "<redacted>")
	// Replace -H "Cookie: <anything>" patterns.
	curl = redactCurlHeader(curl, "Cookie", "<cookie>")
	return curl
}

// redactCurlHeader replaces the value portion of a named HTTP header inside a
// curl -H "Name: value" argument. It handles both double-quoted and unquoted forms.
func redactCurlHeader(curl, name, sentinel string) string {
	// We do a simple string search for the header name (case-insensitive prefix match).
	// curl -H arguments are typically: -H "HeaderName: value"
	lower := strings.ToLower(curl)
	prefix := strings.ToLower(name + ": ")
	start := 0
	for {
		idx := strings.Index(lower[start:], prefix)
		if idx < 0 {
			break
		}
		abs := start + idx
		// Find end of the header value: either closing quote or end of line.
		valStart := abs + len(prefix)
		end := strings.IndexAny(curl[valStart:], "\"\n")
		if end < 0 {
			end = len(curl) - valStart
		}
		curl = curl[:valStart] + sentinel + curl[valStart+end:]
		lower = strings.ToLower(curl)
		start = valStart + len(sentinel)
	}
	return curl
}

// redactRawHeaderBlock applies the same per-header redaction rules as
// redactHeaders to a raw HTTP header block. Raw blocks are line-structured
// (request/status line, then "Name: value" lines), so selective scrubbing is
// possible after all — the historical blanket-blanking threw away the whole
// evidence block on any redaction mode, so the Request/Response sections the
// publishers promise never appeared. Lines that do not parse as a header are
// replaced entirely (fail closed): the -redact guarantee that sensitive values
// are gone outranks evidence fidelity.
func redactRawHeaderBlock(raw string, ro RedactOptions) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		suffix := line[len(trimmed):] // preserve a trailing \r
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		colon := strings.Index(trimmed, ":")
		// A valid header name is a token with no whitespace before the colon.
		// Whitespace before the colon (or no colon) means the line is not a
		// clean "Name: value" header.
		nameMalformed := colon < 0 || strings.ContainsAny(trimmed[:colon], " \t")
		if i == 0 && nameMalformed {
			// Request/status start-line, NOT a header — "GET https://h/p HTTP/1.1"
			// and "HTTP/1.1 200 OK" have whitespace before any colon (or none).
			// Reuse the _line rule via redactHeaders so URL host/query redaction
			// stays in one place.
			if ro.Domain || ro.Query {
				scrubbed := redactHeaders([]Header{{Name: "_line", Value: trimmed}}, ro)
				lines[i] = scrubbed[0].Value + suffix
			}
			continue
		}
		if nameMalformed {
			// Fail closed: a non-start-line that does not parse as a clean header
			// (no colon, or whitespace in the name) is replaced entirely rather
			// than risk a sensitive value slipping past the name-based rules.
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

func redactHeaders(hs []Header, ro RedactOptions) []Header {
	if len(hs) == 0 {
		return hs
	}
	out := make([]Header, 0, len(hs))
	for _, h := range hs {
		name := strings.ToLower(strings.TrimSpace(h.Name))
		v := h.Value
		// Request/status line may contain a full URL; redact host/query if requested.
		if name == "_line" && (ro.Domain || ro.Query) {
			parts := strings.Fields(v)
			if len(parts) >= 2 {
				parts[1] = redactURL(parts[1], ro)
				v = strings.Join(parts, " ")
			}
		}
		if ro.Cookies && (name == "cookie" || name == "set-cookie") {
			v = "<redacted>"
		}
		if ro.Auth && name == "authorization" {
			v = "<redacted>"
		}
		if ro.Headers {
			switch name {
			case "x-api-key", "api-key", "x-auth-token", "x-access-token", "authentication":
				v = "<redacted>"
			}
		}
		if ro.Domain {
			if name == "host" || name == ":authority" {
				v = "<redacted>"
			}
			// redact embedded URLs in referer/origin
			if name == "referer" || name == "origin" {
				v = redactURL(v, ro)
			}
		}
		out = append(out, Header{Name: h.Name, Value: v})
	}
	return out
}
