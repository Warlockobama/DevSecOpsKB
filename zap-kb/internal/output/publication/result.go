// Package publication defines portable, sanitized destination outcomes. It has
// no process-exit or artifact-writing side effects; orchestration owns both.
package publication

import "fmt"

type Status string

const (
	Successful Status = "successful"
	Partial    Status = "partial"
	Failed     Status = "failed"
	Skipped    Status = "skipped"
)

// Diagnostic must contain only sanitized diagnostics, never raw remote bodies,
// request URLs, credentials, or captured evidence. Field IDs are allowlisted by
// the destination adapter; Message is a bounded actionable explanation.
type Diagnostic struct {
	FindingID  string            `json:"findingId,omitempty"`
	Stage      string            `json:"stage"`
	HTTPStatus int               `json:"httpStatus,omitempty"`
	Category   string            `json:"category"`
	Retryable  bool              `json:"retryable"`
	Message    string            `json:"message"`
	Fields     []FieldDiagnostic `json:"fields,omitempty"`
}

type FieldDiagnostic struct {
	Field    string `json:"field"`
	Category string `json:"category"`
	Message  string `json:"message"`
}

type StageResult struct {
	Destination string        `json:"destination"`
	Stage       string        `json:"stage"`
	Status      Status        `json:"status"`
	Required    bool          `json:"required"`
	Attempted   int           `json:"attempted"`
	Succeeded   int           `json:"succeeded"`
	Skipped     int           `json:"skipped"`
	Failed      int           `json:"failed"`
	Diagnostics []Diagnostic  `json:"diagnostics,omitempty"`
	DurationMS  int64         `json:"durationMs,omitempty"`
	Requests    int64         `json:"requests,omitempty"`
	Phases      []PhaseMetric `json:"phases,omitempty"`
}

// PhaseMetric carries aggregate request timing only; never URLs or bodies.
type PhaseMetric struct {
	Phase      string `json:"phase"`
	DurationMS int64  `json:"durationMs"`
	Requests   int    `json:"requests"`
	Retries    int    `json:"retries"`
}

type Result struct {
	Stages []StageResult `json:"stages"`
}

func (r Result) Err() error {
	n := 0
	for _, s := range r.Stages {
		if s.Required && (s.Status == Failed || s.Status == Partial || s.Failed > 0) {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return fmt.Errorf("publication: %d required stage(s) failed; inspect publication results", n)
}

// Outcome treats successful no-op lookups as completed work. A deliberately
// omitted stage (dry run, prerequisite unavailable) must explicitly use Skipped.
func Outcome(succeeded, skipped, failed int) Status {
	if failed == 0 {
		return Successful
	}
	if succeeded+skipped > 0 {
		return Partial
	}
	return Failed
}
