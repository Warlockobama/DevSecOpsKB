package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type EvidenceLinkSummary struct {
	Added   int
	Skipped int
	Errors  int
}

func SyncFindingEvidenceLinks(ctx context.Context, ticketKeys, findingLinks map[string]string, opts Options) (EvidenceLinkSummary, error) {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.APIToken) == "" {
		return EvidenceLinkSummary{}, fmt.Errorf("jira evidence link sync: missing required fields (base URL, username, api token)")
	}
	if len(ticketKeys) == 0 || len(findingLinks) == 0 {
		return EvidenceLinkSummary{}, nil
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	if concurrency > 5 {
		concurrency = 5
	}
	delay := opts.RequestDelay
	if delay == 0 {
		delay = 250 * time.Millisecond
	}
	rawClient := &http.Client{Timeout: opts.Timeout}
	if rawClient.Timeout == 0 {
		rawClient.Timeout = 30 * time.Second
	}
	client := newThrottledClient(rawClient, delay)
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(opts.Username)+":"+strings.TrimSpace(opts.APIToken)))
	base := strings.TrimRight(opts.BaseURL, "/")

	type candidate struct {
		issueKey string
		url      string
	}
	var candidates []candidate
	for findingID, issueKey := range ticketKeys {
		issueKey = strings.TrimSpace(issueKey)
		link := strings.TrimSpace(findingLinks[findingID])
		if issueKey == "" || link == "" {
			continue
		}
		candidates = append(candidates, candidate{issueKey: issueKey, url: link})
	}
	if len(candidates) == 0 {
		return EvidenceLinkSummary{}, nil
	}

	type result struct {
		added   bool
		skipped bool
		err     error
	}
	results := make([]result, len(candidates))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, c := range candidates {
		wg.Add(1)
		go func(i int, c candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			exists, err := hasRemoteLink(ctx, client, auth, base, c.issueKey, c.url)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			if exists {
				results[i] = result{skipped: true}
				return
			}
			if err := addRemoteLink(ctx, client, auth, base, c.issueKey, c.url); err != nil {
				results[i] = result{err: err}
				return
			}
			results[i] = result{added: true}
		}(i, c)
	}
	wg.Wait()

	var sum EvidenceLinkSummary
	for _, r := range results {
		if r.err != nil {
			sum.Errors++
			continue
		}
		if r.added {
			sum.Added++
		} else if r.skipped {
			sum.Skipped++
		}
	}
	return sum, nil
}

func hasRemoteLink(ctx context.Context, client httpDoer, auth, base, issueKey, wantURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/api/3/issue/"+issueKey+"/remotelink", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var links []struct {
		Object struct {
			URL string `json:"url"`
		} `json:"object"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&links); err != nil {
		return false, fmt.Errorf("decode remote links: %w", err)
	}
	for _, link := range links {
		if strings.TrimSpace(link.Object.URL) == wantURL {
			return true, nil
		}
	}
	return false, nil
}

func addRemoteLink(ctx context.Context, client httpDoer, auth, base, issueKey, targetURL string) error {
	payload := map[string]any{
		"object": map[string]any{
			"url":   targetURL,
			"title": "Confluence Finding Evidence",
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal remote link: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/3/issue/"+issueKey+"/remotelink", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
