package entities

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
)

// ParseRedactOptions is the strict output-boundary parser. Diagnostics never
// repeat the supplied token, which can itself contain private input.
func ParseRedactOptions(list string) (RedactOptions, error) {
	for _, v := range strings.FieldsFunc(strings.ToLower(list), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		switch v {
		case "domain", "query", "cookies", "cookie", "auth", "authorization", "headers", "header", "body", "notes", "note", "secrets", "secret", "pii", "credentials":
		default:
			return RedactOptions{}, errors.New("unknown redaction mode; use domain,query,cookies,auth,headers,body,notes,secrets")
		}
	}
	return ParseRedactOptionList(list), nil
}

func (ro RedactOptions) Enabled() bool { return ro != (RedactOptions{}) }

// RedactStringMap derives display-only metadata without mutating a publisher's
// remote state lookup. Keys (ticket references) are stable correlation IDs.
func RedactStringMap(values map[string]string, ro RedactOptions) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = RedactText(value, ro)
	}
	return out
}

var embeddedURL = regexp.MustCompile(`(?i)https?://[^\s<>"'` + "`" + `]+`)
var embeddedQuery = regexp.MustCompile(`([?&][^=\s&<>"']+=)[^&\s<>"'#` + "`" + `]+`)
var headerText = regexp.MustCompile(`(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|authentication)\s*:\s*[^\r\n"'` + "`" + `]*`)
var credentialText = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*[^\s,;"'<>]+`)
var curlCookie = regexp.MustCompile(`(?:--cookie|-b)\s+(?:"[^"]*"|'[^']*'|\S+)`)
var curlAuth = regexp.MustCompile(`(?:--user|--oauth2-bearer|-u)\s+(?:"[^"]*"|'[^']*'|\S+)`)

// RedactText protects free text, including URLs inside names, curl commands,
// descriptions, analyst history, and producer metadata. Opaque arbitrary
// secrets require their structured mode (body/notes), not pattern guessing.
func RedactText(s string, ro RedactOptions) string {
	if !ro.Enabled() {
		return s
	}
	if ro.Domain || ro.Query || ro.Auth {
		s = embeddedURL.ReplaceAllStringFunc(s, func(v string) string { return redactURL(v, ro) })
	}
	if ro.Query {
		s = embeddedQuery.ReplaceAllString(s, "${1}<redacted>")
	}
	if ro.Cookies {
		s = curlCookie.ReplaceAllString(s, `--cookie "<redacted>"`)
	}
	if ro.Auth {
		s = curlAuth.ReplaceAllString(s, `--user "<redacted>"`)
	}
	s = headerText.ReplaceAllStringFunc(s, func(v string) string {
		colon := strings.Index(v, ":")
		name := strings.ToLower(strings.TrimSpace(v[:colon]))
		if sensitiveHeader(name, ro) {
			return v[:colon+1] + " <redacted>"
		}
		return v
	})
	if ro.Secrets {
		s = redactSecretsText(s)
		s = credentialText.ReplaceAllString(s, "<redacted-credential>")
	}
	return s
}

func sensitiveHeader(name string, ro RedactOptions) bool {
	switch strings.ToLower(name) {
	case "cookie", "set-cookie":
		return ro.Cookies
	case "authorization", "proxy-authorization":
		return ro.Auth
	case "x-api-key", "api-key", "x-auth-token", "x-access-token", "authentication":
		return ro.Headers
	}
	return false
}

// RedactOutput applies one policy to a mutable *struct/*slice output view.
// Callers construct identities and validate BEFORE creating this view. The
// walker covers additive modeled strings without serializing identity fields
// through a lossy untyped number conversion. JSON-encoded producer evidence is
// decoded separately with UseNumber to retain trace numbers and structure.
func RedactOutput(value interface{}, ro RedactOptions) { redactValue(reflect.ValueOf(value), "", ro) }

func identityField(key string) bool {
	switch strings.ToLower(key) {
	case "definitionid", "findingid", "occurrenceid", "occurrenceref", "entryid", "pluginid", "sourceid", "sourcetool", "scanlabel", "recurredinscan", "schema", "schemaversion", "bodyhash", "commit":
		return true
	}
	return false
}

func redactField(key, s string, ro RedactOptions) string {
	if identityField(key) {
		return s
	}
	key = strings.ToLower(key)
	if ro.Query && (key == "query" || key == "querystring" || key == "queryparams") {
		return "<redacted>"
	}
	if ro.Domain && (key == "host" || key == "hostname" || key == "domain") {
		return "<redacted>"
	}
	if ro.Body {
		switch key {
		case "body", "bodysnippet", "requestbody", "responsebody", "attack", "evidence", "curl":
			return ""
		}
	}
	if ro.Notes {
		switch key {
		case "notes", "note", "rationale", "reason", "steps":
			return ""
		}
	}
	if sensitiveHeader(key, ro) {
		return "<redacted>"
	}
	if ro.Secrets {
		switch key {
		case "password", "passwd", "token", "secret", "apikey", "api_key", "credentials":
			return "<redacted>"
		}
	}
	if key == "rawheader" || key == "requestheader" || key == "responseheader" {
		s = redactRawHeaderBlock(s, ro)
	}
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var v interface{}
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		var trailing interface{}
		if dec.Decode(&v) == nil && dec.Decode(&trailing) == io.EOF {
			v = redactJSON(v, key, ro)
			if b, err := json.Marshal(v); err == nil {
				return string(b)
			}
		}
	}
	if ro.Body && key == "other" {
		return ""
	}
	return RedactText(s, ro)
}

func redactJSON(v interface{}, key string, ro RedactOptions) interface{} {
	// Sensitive subtrees may be structured objects, arrays or numbers. Their
	// protection cannot depend on the producer choosing a string encoding.
	name := strings.ToLower(key)
	if !identityField(name) {
		if ro.Body {
			switch name {
			case "body", "bodysnippet", "requestbody", "responsebody", "attack", "evidence", "curl":
				return ""
			}
		}
		if ro.Notes {
			switch name {
			case "notes", "note", "rationale", "reason", "steps":
				return ""
			}
		}
		if sensitiveHeader(name, ro) {
			return "<redacted>"
		}
		if ro.Secrets {
			switch name {
			case "password", "passwd", "token", "secret", "apikey", "api_key", "credentials":
				return "<redacted>"
			}
		}
	}
	switch t := v.(type) {
	case string:
		return redactField(key, t, ro)
	case []interface{}:
		for i := range t {
			t[i] = redactJSON(t[i], key, ro)
		}
	case map[string]interface{}:
		// Header objects use a name/value pair rather than a semantic key.
		if name, ok := t["name"].(string); ok && sensitiveHeader(name, ro) {
			if _, ok := t["value"]; ok {
				t["value"] = "<redacted>"
			}
		}
		for k, x := range t {
			if ro.Query && (strings.EqualFold(key, "query") || strings.EqualFold(key, "queryparams")) {
				t[k] = "<redacted>"
				continue
			}
			t[k] = redactJSON(x, k, ro)
		}
	}
	return v
}

func redactValue(v reflect.Value, key string, ro RedactOptions) {
	if !ro.Enabled() || !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			redactValue(v.Elem(), key, ro)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(Header{}) && v.CanAddr() {
			h := v.Addr().Interface().(*Header)
			*h = redactHeaders([]Header{*h}, ro)[0]
		}
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if v.Type() == reflect.TypeOf(Taxonomy{}) && field.Name == "ATTACK" {
				continue
			}
			if field.PkgPath != "" {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "" {
				tag = field.Name
			}
			redactValue(v.Field(i), tag, ro)
		}
		raw, size := v.FieldByName("RawHeader"), v.FieldByName("RawHeaderBytes")
		if raw.IsValid() && size.IsValid() && size.CanSet() {
			size.SetInt(int64(len(raw.String())))
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			redactValue(v.Index(i), key, ro)
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(redactField(key, v.String(), ro))
		}
	}
}
