package entities

import (
	neturl "net/url"
	"path"
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
type RedactOptions struct {
	Domain  bool
	Query   bool
	Cookies bool
	Auth    bool
	Headers bool
	Body    bool
	Notes   bool
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
		if i == 0 && (colon < 0 || strings.ContainsAny(trimmed[:colon], " \t")) {
			// Request/status start-line, NOT a header — a header name has no
			// whitespace before its colon, whereas "GET https://h/p HTTP/1.1"
			// and "HTTP/1.1 200 OK" do (or have no colon). Reuse the _line rule
			// via redactHeaders so URL host/query redaction stays in one place.
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
