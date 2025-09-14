package zapclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client wraps minimal config for ZAP API calls.
type Client struct {
	BaseURL    *url.URL
	APIKey     string
	HTTPClient *http.Client
}

// NewClient constructs a client. base should be like "http://127.0.0.1:8090"
func NewClient(base, apiKey string) (*Client, error) {
	if base == "" {
		return nil, errors.New("base URL required")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	hc := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	return &Client{BaseURL: u, APIKey: apiKey, HTTPClient: hc}, nil
}

func (c *Client) build(path string, q url.Values) *url.URL {
	u := *c.BaseURL // copy
	u.Path = path
	if q == nil {
		q = url.Values{}
	}
	if c.APIKey != "" {
		// ZAP accepts the key as query param or header; well do both for convenience.
		q.Set("apikey", c.APIKey)
	}
	u.RawQuery = q.Encode()
	return &u
}

func (c *Client) do(ctx context.Context, req *http.Request) ([]byte, error) {
	if c.APIKey != "" {
		req.Header.Set("X-ZAP-API-Key", c.APIKey)
	}
	req = req.WithContext(ctx)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("zap api %s: %s", resp.Status, string(b))
	}
	return io.ReadAll(resp.Body)
}

// GetAlerts hits /JSON/core/view/alerts with optional filters and paging.
// It returns the alerts slice exactly as ZAP provides it (mapped to Alert).
func (c *Client) GetAlerts(ctx context.Context, f AlertsFilter) ([]Alert, error) {
	q := url.Values{}
	if f.BaseURL != "" {
		q.Set("baseurl", f.BaseURL)
	}
	if f.URL != "" {
		q.Set("url", f.URL)
	}
	if f.RiskID != "" {
		q.Set("riskId", f.RiskID)
	}
	if f.ContextName != "" {
		q.Set("contextName", f.ContextName)
	}
	if f.Regex {
		q.Set("regex", "true")
	}
	if f.Recurse {
		q.Set("recurse", "true")
	}
	if f.Start > 0 {
		q.Set("start", strconv.Itoa(f.Start))
	}
	if f.Count > 0 {
		q.Set("count", strconv.Itoa(f.Count))
	}

	endpoint := c.build("/JSON/core/view/alerts", q)
	req, _ := http.NewRequest("GET", endpoint.String(), nil)
	body, err := c.do(ctx, req)
	if err != nil {
		return nil, err
	}

	// Response shape: { "alerts": [ { ... }, ... ] }
	var wrapper struct {
		Alerts []Alert `json:"alerts"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("unmarshal alerts: %w", err)
	}
	return wrapper.Alerts, nil
}

// GetActiveScanStatus returns the integer % complete for an ascan ID.
// /JSON/ascan/view/status/?scanId=#
func (c *Client) GetActiveScanStatus(ctx context.Context, scanID int) (int, error) {
	q := url.Values{}
	q.Set("scanId", strconv.Itoa(scanID))
	endpoint := c.build("/JSON/ascan/view/status", q)
	req, _ := http.NewRequest("GET", endpoint.String(), nil)
	body, err := c.do(ctx, req)
	if err != nil {
		return 0, err
	}

	// GetMessage fetches a single HTTP message by history id (SourceID).
	// /JSON/core/view/message/?id=123
	var wrapper struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return 0, fmt.Errorf("unmarshal status: %w", err)
	}
	percent, _ := strconv.Atoi(wrapper.Status)
	return percent, nil
}

// GetMessage fetches a single HTTP message by history id (SourceID).
// /JSON/core/view/message/?id=123
func (c *Client) GetMessage(ctx context.Context, id string) (Message, error) {
	q := url.Values{}
	q.Set("id", id)
	endpoint := c.build("/JSON/core/view/message", q)
	req, _ := http.NewRequest("GET", endpoint.String(), nil)
	body, err := c.do(ctx, req)
	if err != nil {
		return Message{}, err
	}
	var wrapper struct {
		Message Message `json:"message"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return Message{}, fmt.Errorf("unmarshal message: %w", err)
	}
	return wrapper.Message, nil
}
