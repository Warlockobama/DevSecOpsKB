// Package forgejo publishes the normalized DevSecOpsKB entities model to a
// Forgejo (or Gitea) instance: findings become issues (with status pull-back)
// and the generated Obsidian markdown vault becomes wiki pages. It is an
// open-source analog to the Atlassian (Jira + Confluence) sink and consumes the
// source-agnostic entities model, so any detection source (ZAP, YARA, Snort,
// link-intelligence, …) that normalizes to entities publishes through it
// unchanged.
package forgejo

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// client bundles the Forgejo REST connection details shared across operations.
// Auth uses a personal access token via the "Authorization: token <PAT>" header
// (Forgejo/Gitea convention), unlike Jira's HTTP Basic.
type client struct {
	http  synccore.HTTPDoer
	base  string // e.g. https://forge.example.com (no trailing slash, no /api/v1)
	token string
	owner string
	repo  string
}

// repoAPI returns the /api/v1/repos/{owner}/{repo} prefix for issue/label calls.
func (c *client) repoAPI() string {
	return c.base + "/api/v1/repos/" + c.owner + "/" + c.repo
}

// newRequest builds an authenticated JSON request. body is the raw, already
// marshaled payload (nil for GET/DELETE without a body).
func (c *client) newRequest(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	var rdr *strings.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, rdr)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// newClient validates connection fields and returns a throttled client.
func newClient(http synccore.HTTPDoer, baseURL, token, owner, repo string) *client {
	return &client{
		http:  http,
		base:  strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token: strings.TrimSpace(token),
		owner: strings.TrimSpace(owner),
		repo:  strings.TrimSpace(repo),
	}
}

// defaultHTTP returns a throttled *http.Client with sane timeouts/delay.
func defaultHTTP(timeout, delay time.Duration) synccore.HTTPDoer {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if delay == 0 {
		delay = 250 * time.Millisecond
	}
	return synccore.NewThrottledClient(&http.Client{Timeout: timeout}, delay)
}
