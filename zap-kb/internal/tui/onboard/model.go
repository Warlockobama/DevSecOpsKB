// Package onboard implements the interactive triage-policy onboarding TUI
// (Bubble Tea). Slice 1c-iii of epic #71. Goal: walk an operator through
// every triage-policy.yaml knob with a paragraph explaining what the knob
// does, sensible defaults pre-filled, and a final review screen before
// writing the YAML.
//
// Why a TUI before a web GUI: the binary already runs in terminals on every
// supported platform; no port-binding, no browser-launching, no extra deps
// beyond bubbletea + bubbles + lipgloss (all single-binary friendly). Slice
// 1c-iv will mirror this flow in HTML for analysts who prefer a browser.
package onboard

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

// step indexes the wizard pages. Welcome → 5 policy fields → review → done.
type step int

const (
	stepWelcome step = iota
	stepAutoReopen
	stepFPSuppressThreshold
	stepFPSuppressExpiry
	stepRuleTuneScan
	stepAcceptedExpiry
	stepReview
	stepDone
)

// Model is the Bubble Tea model. Exported so tests can construct one
// directly and drive Update() without spinning up a real TTY.
type Model struct {
	Policy   config.TriagePolicy // current values being edited
	Path     string              // where to write on save
	step     step
	input    textinput.Model // shared input for the integer/path fields
	err      error
	saved    bool   // true once the YAML write succeeded
	savedTo  string // path actually written
	quitting bool
}

// fieldMeta describes one policy knob: its title, the explanation paragraph
// shown above the input, and the input kind. Kept in a slice so the wizard
// loop is data-driven — adding a new policy field is a one-line entry.
type fieldMeta struct {
	step      step
	title     string
	paragraph string
	// kind: "bool" renders a y/n toggle; "int" renders a textinput.
	kind string
}

func fields() []fieldMeta {
	return []fieldMeta{
		{stepAutoReopen, "Auto-reopen on recurrence",
			"When enabled, findings you've marked false-positive (fp) or fixed are\n" +
				"automatically flipped back to \"open\" if a later scan rediscovers them.\n" +
				"An audit trail entry is appended so you can see why.\n\n" +
				"Disable only if you want recurrence to be advisory and re-triage by hand.\n" +
				"\"accepted\" findings are NEVER auto-reopened (they're time-bounded by\n" +
				"acceptedUntil instead).",
			"bool"},
		{stepFPSuppressThreshold, "False-positive auto-suppression threshold",
			"How many \"analyst-said-fp → detection-found-it-again\" cycles to tolerate\n" +
				"on a single finding before zap-kb auto-suppresses it. Each cycle is one\n" +
				"history entry. After this many cycles, the finding stops appearing in\n" +
				"triage queues until the suppression expires.\n\n" +
				"Recommended: 3. Set 0 to disable auto-suppression entirely.",
			"int"},
		{stepFPSuppressExpiry, "Auto-suppression expiry (days)",
			"How long an auto-written suppression lasts before the finding returns to\n" +
				"the triage queue for reconfirmation. Bounds the \"hide and forget\" risk\n" +
				"so a noisy finding can't disappear forever if the underlying app code\n" +
				"changes.\n\n" +
				"Recommended: 90 days.",
			"int"},
		{stepRuleTuneScan, "Rule tune-scan threshold",
			"Aggregate fp count across every finding sharing a detection rule (same\n" +
				"pluginId). When the rule-wide total crosses this number, the detection\n" +
				"definition is tagged \"tune-scan\" so security engineering knows it's a\n" +
				"high-noise rule worth retuning.\n\n" +
				"Recommended: 5. Set 0 to disable rule-level tagging.",
			"int"},
		{stepAcceptedExpiry, "Accepted-risk default expiry (days)",
			"When an analyst marks a finding \"accepted\" without specifying their own\n" +
				"acceptedUntil date, zap-kb stamps an expiry this many days out. The\n" +
				"acceptance-expired report (slice 2) flags findings whose acceptance has\n" +
				"lapsed so risk decisions get periodically revisited.\n\n" +
				"Recommended: 180 days.",
			"int"},
	}
}

// New builds a Model pre-populated with `start` as the editable policy and
// `outPath` as the YAML write destination.
func New(start config.TriagePolicy, outPath string) Model {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.CharLimit = 8
	ti.Width = 20
	return Model{Policy: start, Path: outPath, step: stepWelcome, input: ti}
}

func (m Model) Init() tea.Cmd { return textinput.Blink }

// Saved reports whether the wizard completed a successful write.
func (m Model) Saved() bool { return m.saved }

// SavedTo returns the path the policy was written to (empty if not saved).
func (m Model) SavedTo() string { return m.savedTo }

// currentField returns the metadata for the current step, or nil for
// non-field steps (welcome, review, done).
func (m Model) currentField() *fieldMeta {
	for _, f := range fields() {
		if f.step == m.step {
			fc := f
			return &fc
		}
	}
	return nil
}

// fieldValue returns the current value being edited as a string for display
// in the textinput / review screen. Bool fields render as "yes"/"no".
func (m Model) fieldValue(s step) string {
	switch s {
	case stepAutoReopen:
		if m.Policy.AutoReopenOnRecurrence {
			return "yes"
		}
		return "no"
	case stepFPSuppressThreshold:
		return strconv.Itoa(m.Policy.FindingFPSuppressionThreshold)
	case stepFPSuppressExpiry:
		return strconv.Itoa(m.Policy.FindingFPSuppressionExpiryDays)
	case stepRuleTuneScan:
		return strconv.Itoa(m.Policy.RuleTuneScanThreshold)
	case stepAcceptedExpiry:
		return strconv.Itoa(m.Policy.AcceptedDefaultExpiryDays)
	}
	return ""
}

// commitInput parses the textinput buffer (or the implicit toggle) into the
// policy struct for the current step. Returns an error if the user's input
// doesn't parse as a non-negative int — surfaced inline rather than dropping
// them off the next screen with a confusing zero.
func (m *Model) commitInput() error {
	raw := strings.TrimSpace(m.input.Value())
	switch m.step {
	case stepAutoReopen:
		// Bool toggled on key press; nothing to commit from textinput.
		return nil
	case stepFPSuppressThreshold:
		v, err := parseNonNeg(raw)
		if err != nil {
			return err
		}
		m.Policy.FindingFPSuppressionThreshold = v
	case stepFPSuppressExpiry:
		v, err := parseNonNeg(raw)
		if err != nil {
			return err
		}
		m.Policy.FindingFPSuppressionExpiryDays = v
	case stepRuleTuneScan:
		v, err := parseNonNeg(raw)
		if err != nil {
			return err
		}
		m.Policy.RuleTuneScanThreshold = v
	case stepAcceptedExpiry:
		v, err := parseNonNeg(raw)
		if err != nil {
			return err
		}
		m.Policy.AcceptedDefaultExpiryDays = v
	}
	return nil
}

func parseNonNeg(raw string) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("empty value (use 0 to disable)")
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("must be an integer")
	}
	if v < 0 {
		return 0, fmt.Errorf("must be >= 0 (use 0 to disable)")
	}
	return v, nil
}

// loadInputForCurrentStep populates the textinput with the current value of
// the policy field at m.step. Called when entering a step so the user sees
// their previous answer (or the default) pre-filled.
func (m *Model) loadInputForCurrentStep() {
	if m.currentField() == nil {
		return
	}
	if m.step == stepAutoReopen {
		m.input.Blur()
		return
	}
	m.input.SetValue(m.fieldValue(m.step))
	m.input.CursorEnd()
	m.input.Focus()
}

// Update is the standard Bubble Tea reducer. Key bindings:
//   - enter / →  advance (commit current input first)
//   - esc / ←    back
//   - q / ctrl+c quit without saving
//   - on review: y / s saves; n / esc backs out
//   - on bool steps: y/n/space toggle the value
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		// Forward non-key messages (e.g. cursor blink ticks from textinput.Blink)
		// to the textinput so blinking works correctly on int-input steps.
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	switch keyMsg.String() {
	case "ctrl+c", "q":
		m.quitting = true
		return m, tea.Quit
	}

	switch m.step {
	case stepWelcome:
		switch keyMsg.String() {
		case "enter", "right":
			m.step = stepAutoReopen
			m.loadInputForCurrentStep()
		}
		return m, nil
	case stepAutoReopen:
		switch keyMsg.String() {
		case "y":
			m.Policy.AutoReopenOnRecurrence = true
		case "n":
			m.Policy.AutoReopenOnRecurrence = false
		case " ":
			m.Policy.AutoReopenOnRecurrence = !m.Policy.AutoReopenOnRecurrence
		case "enter", "right":
			m.step = stepFPSuppressThreshold
			m.loadInputForCurrentStep()
		case "left", "esc":
			m.step = stepWelcome
		}
		return m, nil
	case stepReview:
		switch keyMsg.String() {
		case "y", "s", "enter":
			if err := config.WritePolicy(m.Path, m.Policy); err != nil {
				m.err = err
				return m, nil
			}
			m.saved = true
			m.savedTo = m.Path
			m.step = stepDone
		case "left", "esc", "b":
			m.step = stepAcceptedExpiry
			m.loadInputForCurrentStep()
		}
		return m, nil
	case stepDone:
		switch keyMsg.String() {
		case "enter", "esc":
			return m, tea.Quit
		}
		return m, nil
	}

	// Integer-input steps: textinput drives the buffer; Enter commits and
	// advances, Esc/← goes back without committing.
	switch keyMsg.String() {
	case "enter", "right":
		if err := m.commitInput(); err != nil {
			m.err = err
			return m, nil
		}
		m.err = nil
		m.step++
		if m.step == stepReview {
			return m, nil
		}
		m.loadInputForCurrentStep()
		return m, nil
	case "left", "esc":
		m.err = nil
		if m.step > stepWelcome {
			m.step--
		}
		m.loadInputForCurrentStep()
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// styles for View. Defined once at package scope so we don't re-allocate per
// render. Lipgloss tolerates terminals that don't support color.
var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	helpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
	stepStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	rowKey     = lipgloss.NewStyle().Width(36).Foreground(lipgloss.Color("244"))
	rowVal     = lipgloss.NewStyle().Bold(true)
)

// View is the standard Bubble Tea render. We keep the layout deliberately
// simple — title, paragraph, prompt or summary, footer with key hints — so
// it works in 80-column terminals.
func (m Model) View() string {
	if m.quitting {
		return "Onboarding cancelled. No changes written.\n"
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("zap-kb triage policy onboarding") + "\n")
	b.WriteString(stepStyle.Render(fmt.Sprintf("step %d of %d", int(m.step)+1, int(stepDone)+1)) + "\n\n")

	switch m.step {
	case stepWelcome:
		b.WriteString("This wizard walks you through the operator-tunable knobs that\n")
		b.WriteString("control how zap-kb auto-triages recurring findings.\n\n")
		b.WriteString("Each step explains the setting; the recommended default is pre-filled.\n")
		b.WriteString("You can revisit any answer with ← / esc, and a final review lets you\n")
		b.WriteString("confirm everything before writing " + m.Path + ".\n\n")
		b.WriteString(helpStyle.Render("press enter to begin · q to quit"))
	case stepReview:
		b.WriteString(titleStyle.Render("Review") + "\n\n")
		b.WriteString(rowKey.Render("Auto-reopen on recurrence") + rowVal.Render(m.fieldValue(stepAutoReopen)) + "\n")
		b.WriteString(rowKey.Render("FP auto-suppression threshold") + rowVal.Render(m.fieldValue(stepFPSuppressThreshold)) + "\n")
		b.WriteString(rowKey.Render("FP auto-suppression expiry days") + rowVal.Render(m.fieldValue(stepFPSuppressExpiry)) + "\n")
		b.WriteString(rowKey.Render("Rule tune-scan threshold") + rowVal.Render(m.fieldValue(stepRuleTuneScan)) + "\n")
		b.WriteString(rowKey.Render("Accepted default expiry days") + rowVal.Render(m.fieldValue(stepAcceptedExpiry)) + "\n\n")
		b.WriteString("Will write to: " + m.Path + "\n\n")
		if m.err != nil {
			b.WriteString(errorStyle.Render("write failed: "+m.err.Error()) + "\n\n")
		}
		b.WriteString(helpStyle.Render("y / s / enter — save · ← / esc — back · q — quit"))
	case stepDone:
		if m.saved {
			b.WriteString(okStyle.Render("✓ Saved triage policy to "+m.savedTo) + "\n\n")
		}
		b.WriteString("zap-kb will pick this up automatically on the next run.\n")
		b.WriteString("Run `zap-kb config show` to confirm.\n\n")
		b.WriteString(helpStyle.Render("press enter to exit"))
	default:
		f := m.currentField()
		if f == nil {
			return b.String()
		}
		b.WriteString(titleStyle.Render(f.title) + "\n\n")
		b.WriteString(f.paragraph + "\n\n")
		if m.step == stepAutoReopen {
			cur := "no"
			if m.Policy.AutoReopenOnRecurrence {
				cur = "yes"
			}
			b.WriteString("current: " + rowVal.Render(cur) + "\n")
			b.WriteString(helpStyle.Render("y — yes · n — no · space — toggle · enter — next · ← — back"))
		} else {
			b.WriteString(m.input.View() + "\n")
			if m.err != nil {
				b.WriteString(errorStyle.Render(m.err.Error()) + "\n")
			}
			b.WriteString(helpStyle.Render("enter — next · ← — back · q — quit"))
		}
	}
	return b.String() + "\n"
}
