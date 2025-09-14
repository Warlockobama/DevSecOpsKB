package zapclient

import (
	"context"
)

const pageSize = 200

// GetAllAlerts pages through /alerts until empty page.
func (c *Client) GetAllAlerts(ctx context.Context, f AlertsFilter) ([]Alert, error) {
	if f.Count == 0 {
		f.Count = pageSize
	}
	var out []Alert
	for {
		chunk, err := c.GetAlerts(ctx, f)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			break
		}
		out = append(out, chunk...)
		f.Start += len(chunk)
	}
	return out, nil
}
