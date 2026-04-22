package onboard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

// send feeds a string of Bubble Tea key events (or named keys) into a model
// and returns the updated model. Keeps the tests short and lets us express
// flows like "enter, enter, '5', enter" without twenty lines of setup.
func send(t *testing.T, m Model, keys ...string) Model {
	t.Helper()
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "left":
			msg = tea.KeyMsg{Type: tea.KeyLeft}
		case "right":
			msg = tea.KeyMsg{Type: tea.KeyRight}
		case "space":
			msg = tea.KeyMsg{Type: tea.KeySpace}
		case "backspace":
			msg = tea.KeyMsg{Type: tea.KeyBackspace}
		default:
			// single character — type it via Runes
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		next, _ := m.Update(msg)
		m = next.(Model)
	}
	return m
}

// TestModel_FullHappyPath: start from defaults, walk through every step
// pressing enter each time, accept all pre-filled values, save. Verifies
// the basic flow compiles and a YAML is written.
func TestModel_FullHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "triage-policy.yaml")
	m := New(config.DefaultPolicy(), path)

	// welcome → auto-reopen → 4 int steps → review → save
	m = send(t, m,
		"enter", // leave welcome
		"enter", // accept auto-reopen=true
		"enter", // accept FP threshold
		"enter", // accept FP expiry
		"enter", // accept rule tune-scan
		"enter", // accept accepted expiry → review
		"y",     // save
	)
	if !m.Saved() {
		t.Fatalf("expected saved=true after pressing y on review, got step=%d err=%v", m.step, m.err)
	}
	if m.SavedTo() != path {
		t.Errorf("SavedTo: want %q, got %q", path, m.SavedTo())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written policy: %v", err)
	}
	if !strings.Contains(string(data), "autoReopenOnRecurrence: true") {
		t.Errorf("written YAML should contain autoReopenOnRecurrence: true, got:\n%s", data)
	}
}

// TestModel_EditInts: type over the pre-filled threshold, verify it lands in
// the policy struct at review time.
func TestModel_EditInts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	m := New(config.DefaultPolicy(), path)
	// welcome → auto-reopen → threshold step
	m = send(t, m, "enter", "enter")
	// Clear the pre-filled value (default "3") and type "7"
	m.input.SetValue("7")
	// Advance
	m = send(t, m, "enter", "enter", "enter", "enter")
	if m.Policy.FindingFPSuppressionThreshold != 7 {
		t.Errorf("threshold: want 7, got %d", m.Policy.FindingFPSuppressionThreshold)
	}
	if m.step != stepReview {
		t.Errorf("expected to land on review, got step=%d", m.step)
	}
}

// TestModel_InvalidIntSurfacesError: typing "abc" into an int field must
// keep the user on that step with an error banner, not silently write 0.
func TestModel_InvalidIntSurfacesError(t *testing.T) {
	m := New(config.DefaultPolicy(), "/tmp/ignored.yaml")
	// welcome → auto-reopen → FP threshold
	m = send(t, m, "enter", "enter")
	m.input.SetValue("abc")
	// Try to advance
	m = send(t, m, "enter")
	if m.err == nil {
		t.Error("expected error on non-integer input, got nil")
	}
	if m.step != stepFPSuppressThreshold {
		t.Errorf("step must not advance on invalid input, got %d", m.step)
	}
}

// TestModel_BoolToggle: y/n/space flip the auto-reopen bool correctly.
func TestModel_BoolToggle(t *testing.T) {
	m := New(config.DefaultPolicy(), "/tmp/ignored.yaml")
	m = send(t, m, "enter") // welcome → auto-reopen step
	if !m.Policy.AutoReopenOnRecurrence {
		t.Fatal("default must start true")
	}
	m = send(t, m, "n")
	if m.Policy.AutoReopenOnRecurrence {
		t.Error("pressing n must set AutoReopen=false")
	}
	m = send(t, m, "space")
	if !m.Policy.AutoReopenOnRecurrence {
		t.Error("space must toggle back to true")
	}
	m = send(t, m, "y")
	if !m.Policy.AutoReopenOnRecurrence {
		t.Error("y must set AutoReopen=true")
	}
}

// TestModel_Back: advancing and then pressing left returns to the previous
// step. Values typed on the later step are preserved so the user can walk
// forward-back without losing work.
func TestModel_Back(t *testing.T) {
	m := New(config.DefaultPolicy(), "/tmp/ignored.yaml")
	m = send(t, m, "enter", "enter") // → FP threshold
	if m.step != stepFPSuppressThreshold {
		t.Fatalf("setup: expected FP threshold, got %d", m.step)
	}
	m = send(t, m, "left")
	if m.step != stepAutoReopen {
		t.Errorf("left must back up to auto-reopen, got %d", m.step)
	}
}

// TestModel_Quit: pressing q sets quitting=true and View renders the
// cancellation message. The tea.Quit cmd is returned by Update but we don't
// drive a real program here so we just check the model flag.
func TestModel_Quit(t *testing.T) {
	m := New(config.DefaultPolicy(), "/tmp/ignored.yaml")
	m = send(t, m, "q")
	if !m.quitting {
		t.Error("q must set quitting=true")
	}
	if !strings.Contains(m.View(), "cancelled") {
		t.Errorf("View after quit should say cancelled, got:\n%s", m.View())
	}
}
