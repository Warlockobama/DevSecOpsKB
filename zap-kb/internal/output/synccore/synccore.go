// Package synccore holds tracker-agnostic plumbing shared by the issue/wiki
// sink publishers (jira, forgejo, …): a rate-limited HTTP client, retry/backoff,
// error-body redaction, and severity filtering. Keeping these in one place lets
// new sinks reuse the proven mechanics instead of copy-pasting them.
package synccore

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPDoer abstracts HTTP request execution so callers can throttle requests
// and tests can stub responses without a live server.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ThrottledClient wraps an *http.Client with a minimum delay between requests.
// Safe for concurrent use; the delay is enforced across all goroutines.
type ThrottledClient struct {
	inner *http.Client
	mu    sync.Mutex
	last  time.Time
	delay time.Duration
}

// NewThrottledClient returns a ThrottledClient enforcing at least delay between
// successive requests.
func NewThrottledClient(inner *http.Client, delay time.Duration) *ThrottledClient {
	return &ThrottledClient{inner: inner, delay: delay}
}

// Do enforces the configured inter-request delay, then delegates to the wrapped
// client. It honors request-context cancellation while waiting.
func (tc *ThrottledClient) Do(req *http.Request) (*http.Response, error) {
	tc.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(tc.last)
	if elapsed < tc.delay {
		remaining := tc.delay - elapsed
		tc.last = now.Add(remaining)
		tc.mu.Unlock()
		select {
		case <-time.After(remaining):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	} else {
		tc.last = now
		tc.mu.Unlock()
	}
	return tc.inner.Do(req)
}

// DoWithRetry executes a request with retries (see DoWithRetryRaw) and
// converts any terminal non-2xx response into a redacted error. The caller
// owns closing the body of a successful response.
func DoWithRetry(client HTTPDoer, req *http.Request, maxAttempts int) (*http.Response, error) {
	resp, err := DoWithRetryRaw(client, req, maxAttempts)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := HTTPError("synccore", resp)
		resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

// retryableStatus reports whether an HTTP status is a transient condition
// worth retrying: 429 (rate limit) and the gateway-flavored 5xx family
// (502/503/504) seen when the backend restarts or a proxy loses it briefly.
// Plain 500 is NOT retried — it is usually deterministic (bad request body,
// server bug) and retrying just triples the noise.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// DoWithRetryRaw executes a request, retrying transient failures with
// exponential backoff (honoring Retry-After when present): HTTP 429/502/503/
// 504 and transport-level errors (connection refused/reset). Context
// cancellation is never retried. The request body is snapshotted once so each
// attempt gets a fresh reader.
//
// Unlike DoWithRetry it returns the final response even when it is non-2xx,
// so callers that treat specific statuses as data (e.g. 404 = "not found")
// can keep doing so while still getting transient-failure resilience.
func DoWithRetryRaw(client HTTPDoer, req *http.Request, maxAttempts int) (*http.Response, error) {
	var bodyData []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyData, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("synccore: read request body: %w", err)
		}
		req.Body.Close()
	}

	backoff := 2 * time.Second
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if bodyData != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyData))
			req.ContentLength = int64(len(bodyData))
		}

		resp, err := client.Do(req)
		if err != nil {
			// Never retry a canceled/expired context; do retry transport blips.
			if ctxErr := req.Context().Err(); ctxErr != nil {
				return nil, ctxErr
			}
			lastErr = err
			if attempt < maxAttempts-1 {
				if !sleepBackoff(req, &backoff) {
					return nil, req.Context().Err()
				}
				continue
			}
			return nil, err
		}
		if retryableStatus(resp.StatusCode) && attempt < maxAttempts-1 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs := parseRetryAfter(ra); secs > 0 {
					backoff = time.Duration(secs) * time.Second
				}
			}
			if !sleepBackoff(req, &backoff) {
				return nil, req.Context().Err()
			}
			continue
		}
		return resp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("synccore: max retries exceeded")
}

// sleepBackoff waits for the current backoff (doubling it, capped at 30s) and
// reports false when the request context ended first.
func sleepBackoff(req *http.Request, backoff *time.Duration) bool {
	select {
	case <-time.After(*backoff):
	case <-req.Context().Done():
		return false
	}
	*backoff *= 2
	if *backoff > 30*time.Second {
		*backoff = 30 * time.Second
	}
	return true
}

func parseRetryAfter(val string) int {
	n := 0
	for _, c := range strings.TrimSpace(val) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// HTTPError reads (a bounded prefix of) the response body and returns a
// descriptive, credential-redacted error tagged with the given system name.
func HTTPError(system string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := SanitizeErrorBody(strings.TrimSpace(string(body)))
	if msg == "" {
		return fmt.Errorf("%s: http %d", system, resp.StatusCode)
	}
	return fmt.Errorf("%s: http %d: %s", system, resp.StatusCode, msg)
}

// SanitizeErrorBody truncates an API error body to 200 chars and redacts
// substrings that look like credentials before the message reaches logs.
func SanitizeErrorBody(s string) string {
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	for _, pat := range []string{"Authorization", "authorization", "token=", "apikey=", "api_key=", "password="} {
		if idx := strings.Index(s, pat); idx >= 0 {
			s = s[:idx] + "<redacted>…"
		}
	}
	return s
}

// SeverityFloor maps a risk string to a numeric code for threshold filtering:
// high=3, medium=2, low=1, everything else (info/unknown/"")=0.
func SeverityFloor(risk string) int {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
