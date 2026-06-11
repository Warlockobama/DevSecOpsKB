package forgejo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// Forgejo/Gitea issues reference labels by numeric ID, not by name (unlike Jira
// which takes label strings directly). ensureLabels resolves a set of label
// names to IDs, creating any that don't yet exist, and returns a name→id map.

const (
	// dedupLabel is attached to every issue this sink creates so the dedup
	// search can scope to KB-managed issues regardless of detection source.
	dedupLabel = "kb-finding"

	// defaultLabelColor is applied to labels this sink auto-creates.
	defaultLabelColor = "#0366d6"
)

// riskLabelColors maps the per-risk labels to their colors; ensureLabels uses
// these when it has to create one, falling back to defaultLabelColor.
var riskLabelColors = map[string]string{
	"risk/high":   "#d73a4a",
	"risk/medium": "#e36209",
	"risk/low":    "#dbab09",
	"risk/info":   "#6a737d",
}

// riskLabel returns the severity label for a finding risk, or "" when the risk
// is unknown.
func riskLabel(risk string) string {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		return "risk/high"
	case "medium":
		return "risk/medium"
	case "low":
		return "risk/low"
	case "info", "informational":
		return "risk/info"
	}
	return ""
}

type forgejoLabel struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// listLabels returns all labels defined on the repo.
func (c *client) listLabels(ctx context.Context) ([]forgejoLabel, error) {
	var all []forgejoLabel
	seen := make(map[int64]bool)
	page := 1
	for {
		url := fmt.Sprintf("%s/labels?limit=50&page=%d", c.repoAPI(), page)
		req, err := c.newRequest(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := synccore.DoWithRetry(c.http, req, 3)
		if err != nil {
			return nil, err
		}
		var batch []forgejoLabel
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&batch); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode labels: %w", err)
		}
		resp.Body.Close()
		// Progress-based termination (see listFindingIssues): stop when a page
		// adds no label IDs we have not already seen. Robust to servers that cap
		// `limit` below 50 and to servers that ignore `page`. Dedup on label ID.
		added := 0
		for _, l := range batch {
			if seen[l.ID] {
				continue
			}
			seen[l.ID] = true
			added++
			all = append(all, l)
		}
		if added == 0 {
			break
		}
		page++
		if page > 1000 {
			return nil, fmt.Errorf("forgejo: label pagination exceeded 1000 pages — aborting (server ignoring page param?)")
		}
	}
	return all, nil
}

// createLabel creates a single repo label and returns it.
func (c *client) createLabel(ctx context.Context, name, color string) (forgejoLabel, error) {
	payload, err := json.Marshal(map[string]string{"name": name, "color": color})
	if err != nil {
		return forgejoLabel{}, err
	}
	req, err := c.newRequest(ctx, http.MethodPost, c.repoAPI()+"/labels", payload)
	if err != nil {
		return forgejoLabel{}, err
	}
	resp, err := synccore.DoWithRetry(c.http, req, 3)
	if err != nil {
		return forgejoLabel{}, err
	}
	defer resp.Body.Close()
	var lbl forgejoLabel
	if err := json.NewDecoder(resp.Body).Decode(&lbl); err != nil {
		return forgejoLabel{}, fmt.Errorf("decode created label: %w", err)
	}
	return lbl, nil
}

// ensureLabels resolves the requested label names to IDs, creating missing
// labels. Comparison is case-insensitive (Forgejo treats label names as
// case-insensitive for matching). Returns a map keyed by the requested name.
func (c *client) ensureLabels(ctx context.Context, names []string) (map[string]int64, error) {
	want := make(map[string]struct{})
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = struct{}{}
		}
	}
	if len(want) == 0 {
		return map[string]int64{}, nil
	}

	existing, err := c.listLabels(ctx)
	if err != nil {
		return nil, err
	}
	byLower := make(map[string]int64, len(existing))
	for _, l := range existing {
		byLower[strings.ToLower(l.Name)] = l.ID
	}

	out := make(map[string]int64, len(want))
	for name := range want {
		if id, ok := byLower[strings.ToLower(name)]; ok {
			out[name] = id
			continue
		}
		color := defaultLabelColor
		if rc, ok := riskLabelColors[strings.ToLower(name)]; ok {
			color = rc
		}
		lbl, err := c.createLabel(ctx, name, color)
		if err != nil {
			// Two publishers can race the first-run create: both list an empty
			// label set, both POST, one loses (409/422). Losing the race is
			// success — re-list and take the winner's label instead of failing
			// the whole export.
			id, ok, lerr := c.findLabelByName(ctx, name)
			if lerr == nil && ok {
				out[name] = id
				byLower[strings.ToLower(name)] = id
				continue
			}
			return nil, fmt.Errorf("create label %q: %w", name, err)
		}
		// Forgejo/Gitea do NOT enforce label-name uniqueness, so a create race
		// can leave two same-named labels — which breaks every name-based
		// label query on the server (`?labels=<name>` returns nothing when
		// the name is ambiguous). Canonicalize: adopt the lowest-id label
		// with this name; if ours turned out to be a duplicate, delete it.
		canonical := lbl.ID
		if id, ok, lerr := c.findLabelByName(ctx, name); lerr == nil && ok && id < canonical {
			canonical = id
			c.deleteLabel(ctx, lbl.ID)
		}
		out[name] = canonical
		byLower[strings.ToLower(name)] = canonical
	}
	return out, nil
}

// findLabelByName re-lists repo labels and returns the LOWEST ID among labels
// with the given name (case-insensitive) — the canonical winner when duplicate
// names exist.
func (c *client) findLabelByName(ctx context.Context, name string) (int64, bool, error) {
	labels, err := c.listLabels(ctx)
	if err != nil {
		return 0, false, err
	}
	var best int64
	found := false
	for _, l := range labels {
		if strings.EqualFold(l.Name, name) && (!found || l.ID < best) {
			best = l.ID
			found = true
		}
	}
	return best, found, nil
}

// deleteLabel removes a repo label. Best-effort duplicate cleanup — errors are
// swallowed because a stale duplicate label is cosmetic once the dedup index
// no longer depends on labels.
func (c *client) deleteLabel(ctx context.Context, id int64) {
	req, err := c.newRequest(ctx, http.MethodDelete, fmt.Sprintf("%s/labels/%d", c.repoAPI(), id), nil)
	if err != nil {
		return
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	drain(resp)
}

// drain fully reads and closes a response body (best effort) so connections can
// be reused.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
