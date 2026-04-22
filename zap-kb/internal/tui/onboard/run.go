package onboard

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

// Run starts the Bubble Tea program with a fresh model pre-populated from
// the policy at `start` and the write-target `path`. Returns the final Model
// so the caller (the CLI subcommand) can inspect whether the user saved and
// print a summary.
//
// Kept separate from model.go so tests can exercise the reducer without
// touching tea.NewProgram (which demands a TTY).
func Run(start config.TriagePolicy, path string) (Model, error) {
	m := New(start, path)
	p := tea.NewProgram(m)
	final, err := p.Run()
	if err != nil {
		return m, err
	}
	if fm, ok := final.(Model); ok {
		return fm, nil
	}
	return m, nil
}
