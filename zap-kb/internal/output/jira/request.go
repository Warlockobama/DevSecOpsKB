package jira

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

func doRequest(client httpDoer, req *http.Request, attempts int) (*http.Response, error) {
	resp, err := synccore.DoWithRetryRaw(client, req, attempts)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = jiraHTTPErr(resp)
		resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

type ambiguousCreateError struct{ cause error }

func (e *ambiguousCreateError) Error() string {
	return "jira: create outcome ambiguous; reconcile before retrying"
}
func (e *ambiguousCreateError) Unwrap() error { return e.cause }

// createOnce never replays a create after a transport failure, 5xx, or malformed
// success response. Even an empty search can lag Jira's index, so reconciliation
// can recover a key but cannot authorize another non-idempotent POST.
func createOnce(client httpDoer, req *http.Request, reconcile func(context.Context) (string, error)) (string, error) {
	if err := req.Context().Err(); err != nil {
		return "", err
	}
	resp, err := synccore.DoWithRetryRaw(client, req, 1)
	// A 429 explicitly rejects this attempt. It is the only create response
	// automatically replayed; all potentially committed outcomes reconcile.
	for attempt := 1; err == nil && resp.StatusCode == http.StatusTooManyRequests && attempt < 3; attempt++ {
		delay := time.Duration(attempt) * time.Second
		if seconds, parseErr := strconv.Atoi(resp.Header.Get("Retry-After")); parseErr == nil && seconds >= 0 {
			delay = time.Duration(seconds) * time.Second
		} else if at, parseErr := http.ParseTime(resp.Header.Get("Retry-After")); parseErr == nil {
			delay = time.Until(at)
		}
		if delay < 0 {
			delay = 0
		}
		if delay > 30*time.Second {
			return "", closeHTTPError(resp)
		}
		resp.Body.Close()
		select {
		case <-time.After(delay):
		case <-req.Context().Done():
			return "", req.Context().Err()
		}
		if req.GetBody != nil {
			req.Body, err = req.GetBody()
			if err != nil {
				return "", err
			}
		}
		resp, err = synccore.DoWithRetryRaw(client, req, 1)
	}
	if err == nil {
		if resp.StatusCode == http.StatusCreated {
			var created struct {
				Key string `json:"key"`
			}
			err = json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&created)
			resp.Body.Close()
			if err == nil && strings.TrimSpace(created.Key) != "" {
				return created.Key, nil
			}
			if err == nil {
				err = errors.New("create response omitted issue key")
			}
		} else {
			status := resp.StatusCode
			err = jiraHTTPErr(resp)
			resp.Body.Close()
			if status < 500 {
				return "", err
			}
		}
	}
	for i := 0; i < 3 && req.Context().Err() == nil; i++ {
		key, lookupErr := reconcile(req.Context())
		if lookupErr != nil {
			break
		}
		if key != "" {
			return key, nil
		}
		if i < 2 {
			select {
			case <-time.After(250 * time.Millisecond):
			case <-req.Context().Done():
			}
		}
	}
	return "", &ambiguousCreateError{cause: err}
}

func closeHTTPError(resp *http.Response) error { defer resp.Body.Close(); return jiraHTTPErr(resp) }
