package obsidian

import "time"

// ReportOptions controls generation of a time-bounded markdown report from an Obsidian vault.
// The current stub exists to satisfy CLI wiring; full implementation can be restored when needed.
type ReportOptions struct {
	OutPath   string
	Title     string
	Since     time.Time
	Until     time.Time
	ScanLabel string
}

// GenerateReport is a placeholder to keep CLI buildable when report generation is not enabled.
// It can be replaced with the full implementation later.
func GenerateReport(root string, opts ReportOptions) error {
	return nil
}
