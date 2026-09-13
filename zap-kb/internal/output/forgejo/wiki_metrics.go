package forgejo

import (
	"net/http"
	"sync"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// WikiPhaseMetric contains only aggregate, non-sensitive measurements. Requests
// counts actual HTTPDoer attempts, including retries; Retries is the subset after
// the first attempt of each logical request. DurationMS is wall time for a phase,
// including request spacing and retry backoff, not summed worker durations.
type WikiPhaseMetric struct {
	Phase      string `json:"phase"`
	DurationMS int64  `json:"duration_ms"`
	Requests   int    `json:"requests"`
	Retries    int    `json:"retries"`
}

type wikiRecorder struct {
	mu      sync.Mutex
	phases  []WikiPhaseMetric
	started time.Time
	active  bool
}

func (r *wikiRecorder) begin(phase string) {
	r.end()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.phases = append(r.phases, WikiPhaseMetric{Phase: phase})
	r.started, r.active = time.Now(), true
}

func (r *wikiRecorder) end() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		r.phases[len(r.phases)-1].DurationMS = time.Since(r.started).Milliseconds()
		r.active = false
	}
}

func (r *wikiRecorder) record(retry bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active {
		return
	}
	p := &r.phases[len(r.phases)-1]
	p.Requests++
	if retry {
		p.Retries++
	}
}

// Each logical request gets its own observer, so counting retries does not
// retain request pointers, headers, credentials or request/response bodies.
type wikiRequestObserver struct {
	inner    synccore.HTTPDoer
	recorder *wikiRecorder
	attempts int
}

func (o *wikiRequestObserver) Do(req *http.Request) (*http.Response, error) {
	if o.recorder != nil {
		o.recorder.record(o.attempts > 0)
	}
	o.attempts++
	return o.inner.Do(req)
}

func (c *client) doWikiRequest(req *http.Request, raw bool) (*http.Response, error) {
	observer := &wikiRequestObserver{inner: c.http, recorder: c.wikiMetrics}
	if raw {
		return synccore.DoWithRetryRaw(observer, req, 3)
	}
	return synccore.DoWithRetry(observer, req, 3)
}
