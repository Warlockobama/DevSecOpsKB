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
type RedactOptions struct {
	Domain  bool
	Query   bool
	Cookies bool
	Auth    bool
	Headers bool
	Body    bool
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
		}
	}
	return ro
}

func RedactEntities(e *EntitiesFile, ro RedactOptions) {
	if e == nil {
		return
	}
	for i := range e.Findings {
		if ro.Domain || ro.Query {
			e.Findings[i].URL = redactURL(e.Findings[i].URL, ro)
		}
	}
	// rawHeaderRedact is true whenever any mode that can expose credentials in the
	// raw header block is active. RawHeader is an unstructured string — we cannot
	// selectively redact it, so we zero the field entirely to preserve the guarantee
	// that -redact removes sensitive values from the output.
	rawHeaderRedact := ro.Cookies || ro.Auth || ro.Headers || ro.Domain || ro.Query

	for i := range e.Occurrences {
		if ro.Domain || ro.Query {
			e.Occurrences[i].URL = redactURL(e.Occurrences[i].URL, ro)
		}
		// headers
		if e.Occurrences[i].Request != nil {
			if ro.Body {
				e.Occurrences[i].Request.BodySnippet = ""
			}
			if rawHeaderRedact {
				e.Occurrences[i].Request.Headers = redactHeaders(e.Occurrences[i].Request.Headers, ro)
				// RawHeader is an unstructured string that cannot be selectively
				// redacted — zero it out to prevent credential bypass.
				e.Occurrences[i].Request.RawHeader = ""
				e.Occurrences[i].Request.RawHeaderBytes = 0
			}
		}
		if e.Occurrences[i].Response != nil {
			if ro.Body {
				e.Occurrences[i].Response.BodySnippet = ""
			}
			if rawHeaderRedact {
				e.Occurrences[i].Response.Headers = redactHeaders(e.Occurrences[i].Response.Headers, ro)
				e.Occurrences[i].Response.RawHeader = ""
				e.Occurrences[i].Response.RawHeaderBytes = 0
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
