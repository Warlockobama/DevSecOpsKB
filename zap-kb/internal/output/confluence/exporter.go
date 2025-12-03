package confluence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
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
func Export(vaultRoot string, opts Options) error {
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

	payload := map[string]any{
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
	if strings.TrimSpace(opts.ParentPageID) != "" {
		payload["ancestors"] = []map[string]string{{"id": strings.TrimSpace(opts.ParentPageID)}}
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	if opts.DryRun {
		fmt.Printf("[confluence] dry-run: would POST %d bytes to %s/rest/api/content (title=%q space=%q parent=%q)\n", len(data), opts.BaseURL, title, opts.SpaceKey, strings.TrimSpace(opts.ParentPageID))
		return nil
	}

	url := strings.TrimRight(opts.BaseURL, "/") + "/rest/api/content"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(opts.Username) + ":" + strings.TrimSpace(opts.APIToken)))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{Timeout: opts.Timeout}
	if client.Timeout == 0 {
		client.Timeout = 30 * time.Second
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("confluence: http %d", resp.StatusCode)
	}
	return nil
}
