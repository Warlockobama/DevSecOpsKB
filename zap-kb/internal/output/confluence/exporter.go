package confluence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options controls Confluence export of a single markdown page (e.g., INDEX.md).
// This is a minimal helper aimed at pushing the KB index into Confluence Server/DC
// via the REST API using a markdown macro wrapper.
type Options struct {
	BaseURL      string
	Username     string
	APIToken     string
	SpaceKey     string
	ParentPageID string
	TitlePrefix  string
	MarkdownPage string // markdown file to upload; default = INDEX.md
	DryRun       bool
	Timeout      time.Duration
}

// Export uploads the specified markdown page (default INDEX.md in vault root) to Confluence.
// Content is wrapped in a markdown macro so existing markdown renders without conversion.
// If a page with the same title already exists in the space, it is updated (upsert).
func Export(ctx context.Context, vaultRoot string, opts Options) error {
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.SpaceKey) == "" || strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.APIToken) == "" {
		return fmt.Errorf("confluence export: missing required fields (base URL, space key, username, api token)")
	}

	page := strings.TrimSpace(opts.MarkdownPage)
	if page == "" {
		page = "INDEX.md"
	}
	mdPath := filepath.Join(vaultRoot, page)
	bodyBytes, err := os.ReadFile(mdPath)
	if err != nil {
		return fmt.Errorf("read markdown: %w", err)
	}
	title := strings.TrimSpace(opts.TitlePrefix + " " + strings.TrimSuffix(page, filepath.Ext(page)))
	title = strings.TrimSpace(title)
	if title == "" {
		title = "KB Index"
	}

	// Wrap markdown in Confluence markdown macro
	markdown := string(bodyBytes)
	macro := "<ac:structured-macro name=\"markdown\"><ac:plain-text-body><![CDATA[\n" + markdown + "\n]]></ac:plain-text-body></ac:structured-macro>"

	if opts.DryRun {
		fmt.Printf("[confluence] dry-run: would upsert %d bytes to %s (title=%q space=%q parent=%q)\n", len(bodyBytes), opts.BaseURL, title, opts.SpaceKey, strings.TrimSpace(opts.ParentPageID))
		return nil
	}

	httpClient := &http.Client{Timeout: opts.Timeout}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 30 * time.Second
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(opts.Username)+":"+strings.TrimSpace(opts.APIToken)))
	base := strings.TrimRight(opts.BaseURL, "/")

	// Check if page already exists (upsert logic)
	existingID, existingVersion, err := findPage(ctx, httpClient, auth, base, opts.SpaceKey, title)
	if err != nil {
		return fmt.Errorf("confluence: find page: %w", err)
	}

	body := map[string]any{
		"type":  "page",
		"title": title,
		"space": map[string]string{"key": opts.SpaceKey},
		"body": map[string]any{
			"storage": map[string]string{
				"value":          macro,
				"representation": "storage",
			},
		},
	}

	if existingID != "" {
		// Update existing page
		body["id"] = existingID
		body["version"] = map[string]int{"number": existingVersion + 1}
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal update payload: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/rest/api/content/"+existingID, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("build update request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		return doRequest(httpClient, req)
	}

	// Create new page
	if strings.TrimSpace(opts.ParentPageID) != "" {
		body["ancestors"] = []map[string]string{{"id": strings.TrimSpace(opts.ParentPageID)}}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal create payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/content", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)
	return doRequest(httpClient, req)
}

// findPage searches for an existing page by title and space key.
// Returns (pageID, versionNumber, error). pageID is empty if not found.
func findPage(ctx context.Context, client *http.Client, auth, base, spaceKey, title string) (string, int, error) {
	q := url.Values{}
	q.Set("title", title)
	q.Set("spaceKey", spaceKey)
	q.Set("expand", "version")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/api/content?"+q.Encode(), nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", auth)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, httpErr(resp)
	}

	var result struct {
		Results []struct {
			ID      string `json:"id"`
			Version struct {
				Number int `json:"number"`
			} `json:"version"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("decode search response: %w", err)
	}
	if len(result.Results) == 0 {
		return "", 0, nil
	}
	r := result.Results[0]
	return r.ID, r.Version.Number, nil
}

// doRequest executes req, checks for a 2xx response, and returns a descriptive error on failure.
func doRequest(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return httpErr(resp)
	}
	return nil
}

// httpErr reads the response body and returns a descriptive error.
func httpErr(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("confluence: http %d", resp.StatusCode)
	}
	return fmt.Errorf("confluence: http %d: %s", resp.StatusCode, msg)
}
