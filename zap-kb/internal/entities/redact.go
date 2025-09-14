package entities

import (
    neturl "net/url"
    "path"
    "strings"
)

// RedactOptions controls redaction.
// Supported keys (case-insensitive):
//   domain   - replace host with <redacted>
//   query    - zero out query parameter values
//   cookies  - redact Cookie and Set-Cookie headers
//   auth     - redact Authorization header value
//   headers  - redact sensitive headers (X-Api-Key, Api-Key, X-Auth-Token)
//   body     - drop BodySnippet values (keep byte counts)
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
    if e == nil { return }
    for i := range e.Findings {
        if ro.Domain || ro.Query {
            e.Findings[i].URL = redactURL(e.Findings[i].URL, ro)
        }
    }
    for i := range e.Occurrences {
        if ro.Domain || ro.Query {
            e.Occurrences[i].URL = redactURL(e.Occurrences[i].URL, ro)
        }
        // headers
        if e.Occurrences[i].Request != nil {
            if ro.Body {
                e.Occurrences[i].Request.BodySnippet = ""
            }
            if ro.Cookies || ro.Auth || ro.Headers {
                e.Occurrences[i].Request.Headers = redactHeaders(e.Occurrences[i].Request.Headers, ro)
            }
        }
        if e.Occurrences[i].Response != nil {
            if ro.Body {
                e.Occurrences[i].Response.BodySnippet = ""
            }
            if ro.Cookies || ro.Auth || ro.Headers {
                e.Occurrences[i].Response.Headers = redactHeaders(e.Occurrences[i].Response.Headers, ro)
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
    if len(hs) == 0 { return hs }
    out := make([]Header, 0, len(hs))
    for _, h := range hs {
        name := strings.ToLower(strings.TrimSpace(h.Name))
        v := h.Value
        if ro.Cookies && (name == "cookie" || name == "set-cookie") {
            v = "<redacted>"
        }
        if ro.Auth && name == "authorization" {
            v = "<redacted>"
        }
        if ro.Headers {
            switch name {
            case "x-api-key", "api-key", "x-auth-token", "x-access-token", "authentication" :
                v = "<redacted>"
            }
        }
        out = append(out, Header{Name: h.Name, Value: v})
    }
    return out
}

