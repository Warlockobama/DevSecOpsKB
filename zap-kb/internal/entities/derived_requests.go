package entities

import (
	"fmt"
	neturl "net/url"
	"strings"
)

const RequestDerivedFromOccurrence = "occurrence-method-url"

// FillDerivedRequests adds a minimal request line when imported traffic contains
// a response but the source artifact did not preserve request headers or body.
func FillDerivedRequests(ef *EntitiesFile) {
	if ef == nil {
		return
	}
	for i := range ef.Occurrences {
		if requestHasDetails(ef.Occurrences[i].Request) || !responseHasDetails(ef.Occurrences[i].Response) {
			continue
		}
		req := deriveRequestFromOccurrence(ef.Occurrences[i].Method, ef.Occurrences[i].URL)
		if req == nil {
			continue
		}
		ef.Occurrences[i].Request = req
	}
}

func requestHasDetails(req *HTTPRequest) bool {
	if req == nil {
		return false
	}
	if strings.TrimSpace(req.RawHeader) != "" ||
		req.RawHeaderBytes > 0 ||
		strings.TrimSpace(req.BodyHash) != "" ||
		strings.TrimSpace(req.BodySnippet) != "" ||
		req.BodyBytes > 0 ||
		strings.TrimSpace(req.DerivedFrom) != "" {
		return true
	}
	return len(nonEmptyHeaders(req.Headers)) > 0
}

func responseHasDetails(resp *HTTPResponse) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode > 0 ||
		strings.TrimSpace(resp.RawHeader) != "" ||
		resp.RawHeaderBytes > 0 ||
		strings.TrimSpace(resp.BodyHash) != "" ||
		strings.TrimSpace(resp.BodySnippet) != "" ||
		resp.BodyBytes > 0 {
		return true
	}
	return len(nonEmptyHeaders(resp.Headers)) > 0
}

func nonEmptyHeaders(headers []Header) []Header {
	out := make([]Header, 0, len(headers))
	for _, h := range headers {
		if strings.TrimSpace(h.Name) == "" && strings.TrimSpace(h.Value) == "" {
			continue
		}
		out = append(out, h)
	}
	return out
}

func deriveRequestFromOccurrence(method, rawURL string) *HTTPRequest {
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil || strings.TrimSpace(u.Host) == "" {
		return nil
	}
	verb := strings.ToUpper(strings.TrimSpace(method))
	if verb == "" {
		verb = "GET"
	}
	target := u.EscapedPath()
	if target == "" {
		target = "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}
	requestLine := fmt.Sprintf("%s %s HTTP/1.1", verb, target)
	rawHeader := requestLine + "\r\nHost: " + u.Host + "\r\n"
	return &HTTPRequest{
		Headers: []Header{
			{Name: "Host", Value: u.Host},
		},
		DerivedFrom:    RequestDerivedFromOccurrence,
		RawHeader:      rawHeader,
		RawHeaderBytes: len(rawHeader),
	}
}
