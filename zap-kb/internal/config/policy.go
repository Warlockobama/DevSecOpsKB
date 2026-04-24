// Package config holds operator-tunable triage policy that the merge pipeline
// and exporters consult instead of hardcoded constants. Policy is loaded from
// triage-policy.yaml in the project root, falling back to the user's config
// home, then to in-process defaults. CLI flags do NOT shadow policy values —
// these are deliberately org-policy decisions, not per-invocation knobs.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// PolicyFileName is the canonical filename the loader looks for.
const PolicyFileName = "triage-policy.yaml"

// TriagePolicy captures every operator-tunable lifecycle decision. Add fields
// here as new behaviors become configurable; do NOT add CLI flags for the same
// values — the YAML file is the single source of truth.
type TriagePolicy struct {
	// AutoReopenOnRecurrence controls whether Merge() flips fp/fixed findings
	// back to "open" when new occurrences arrive (epic #71 slice 1b / issue
	// #57). Disabling this restores the pre-slice-1b behavior where Recurrence
	// is set as advisory only and the analyst manually re-triages.
	AutoReopenOnRecurrence bool `yaml:"autoReopenOnRecurrence"`

	// FindingFPSuppressionThreshold is the number of distinct fp history
	// entries on a single finding required to trigger an auto-Suppression.
	// Slice 1c-ii consumes this. <=0 disables the behavior.
	FindingFPSuppressionThreshold int `yaml:"findingFPSuppressionThreshold"`

	// FindingFPSuppressionExpiryDays is how long an auto-Suppression lasts
	// before it expires and the finding returns to triage queues for
	// re-confirmation. Prevents noisy findings from hiding forever.
	FindingFPSuppressionExpiryDays int `yaml:"findingFPSuppressionExpiryDays"`

	// RuleTuneScanThreshold is the total number of fp transitions (summed
	// across all findings sharing a pluginId) required to tag the
	// Definition with "tune-scan" — the queue security engineering reviews
	// for detection-rule tuning. <=0 disables the behavior.
	RuleTuneScanThreshold int `yaml:"ruleTuneScanThreshold"`

	// AcceptedDefaultExpiryDays is the default acceptedUntil window applied
	// when an analyst marks a finding "accepted" without supplying their own
	// acceptedUntil date. Slice 2 (#58) consumes this for the
	// acceptance-expired report.
	AcceptedDefaultExpiryDays int `yaml:"acceptedDefaultExpiryDays"`
}

// DefaultPolicy returns the built-in defaults used when no YAML is present.
// These are deliberately conservative: behaviors that mutate analyst state
// (auto-reopen) default ON because they're net-positive; thresholds default
// to values that produce signal without being noisy.
func DefaultPolicy() TriagePolicy {
	return TriagePolicy{
		AutoReopenOnRecurrence:         true,
		FindingFPSuppressionThreshold:  3,
		FindingFPSuppressionExpiryDays: 90,
		RuleTuneScanThreshold:          5,
		AcceptedDefaultExpiryDays:      180,
	}
}

// LoadPolicy walks the search path and returns the first policy it finds,
// merged onto DefaultPolicy() so partial YAML files never produce zero-valued
// fields. The second return value is the absolute path of the file that was
// loaded ("" when defaults were used, useful for `config show`).
//
// Search order:
//  1. ./triage-policy.yaml in projectRoot (typically the cwd)
//  2. <user-config-home>/devsecopskb/triage-policy.yaml
//  3. Built-in defaults
//
// Pass projectRoot="" to skip the project-local lookup (useful for tests).
func LoadPolicy(projectRoot string) (TriagePolicy, string, error) {
	candidates := []string{}
	if projectRoot != "" {
		candidates = append(candidates, filepath.Join(projectRoot, PolicyFileName))
	}
	if home, err := userConfigDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, "devsecopskb", PolicyFileName))
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return DefaultPolicy(), "", fmt.Errorf("read %s: %w", path, err)
		}
		abs, aerr := filepath.Abs(path)
		if aerr != nil {
			abs = path
		}
		p, perr := mergeOntoDefaults(data)
		if perr != nil {
			return DefaultPolicy(), abs, fmt.Errorf("parse %s: %w", abs, perr)
		}
		return p, abs, nil
	}
	return DefaultPolicy(), "", nil
}

// mergeOntoDefaults parses YAML over a defaults-initialized struct so any
// field absent from the YAML keeps its default. Use this rather than zero-value
// unmarshal so a user who only wants to override one field doesn't accidentally
// disable everything else.
func mergeOntoDefaults(data []byte) (TriagePolicy, error) {
	p := DefaultPolicy()
	if err := yaml.Unmarshal(data, &p); err != nil {
		return DefaultPolicy(), err
	}
	return p, nil
}

// WriteCommentedDefault writes a heavily commented default YAML to path. Used
// by `zap-kb config init`. Returns an error if the file already exists (the
// caller is responsible for asking before overwriting).
func WriteCommentedDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite", path)
	}
	d := DefaultPolicy()
	content := fmt.Sprintf(`# triage-policy.yaml — operator-tunable triage policy for zap-kb.
#
# Loaded from (in order): ./triage-policy.yaml, then
# <user-config-home>/devsecopskb/triage-policy.yaml, then built-in defaults.
# Any field omitted here keeps its default — partial files are safe.
#
# These are POLICY decisions, not engineering knobs. There are deliberately no
# CLI flags that shadow them — keep policy in this file so it travels with the
# vault and so analysts share a consistent view across runs.

# Auto-reopen findings whose status was fp or fixed when new occurrences
# arrive in a scan. Default: true. Disable to restore the pre-epic-#71-slice-1b
# behavior where Recurrence is an advisory note and the analyst re-triages by
# hand. "accepted" is never auto-reopened — slice 2 handles that via expiry.
autoReopenOnRecurrence: %t

# After this many distinct false-positive history entries on a single finding,
# zap-kb writes an auto-Suppression so the finding stops appearing in triage
# queues. Set <=0 to disable. Slice 1c-ii consumes this.
findingFPSuppressionThreshold: %d

# How many days an auto-Suppression lasts before it expires and the finding
# returns for re-confirmation. Prevents permanent hide-and-forget on findings
# whose context may have changed.
findingFPSuppressionExpiryDays: %d

# Aggregate fp count across all findings under the same pluginId. When the
# total reaches this threshold, the Definition is tagged "tune-scan" so
# security engineering can prioritize tuning the detection rule. Set <=0 to
# disable. Slice 1c-ii consumes this.
ruleTuneScanThreshold: %d

# Default acceptedUntil window applied when an analyst marks a finding
# "accepted" without specifying their own acceptedUntil date. Slice 2 (#58)
# consumes this for the acceptance-expired report.
acceptedDefaultExpiryDays: %d
`,
		d.AutoReopenOnRecurrence,
		d.FindingFPSuppressionThreshold,
		d.FindingFPSuppressionExpiryDays,
		d.RuleTuneScanThreshold,
		d.AcceptedDefaultExpiryDays,
	)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// userConfigDir returns the per-user config dir for devsecopskb files. Wraps
// os.UserConfigDir but tolerates the empty case (returns "" rather than
// erroring; the caller treats missing config dir as "skip that lookup").
func userConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		// On odd platforms os.UserConfigDir can return an error; fall back
		// to ~/.config on unix, %APPDATA% on Windows.
		if home, herr := os.UserHomeDir(); herr == nil && home != "" {
			if runtime.GOOS == "windows" {
				return filepath.Join(home, "AppData", "Roaming"), nil
			}
			return filepath.Join(home, ".config"), nil
		}
		return "", err
	}
	return dir, nil
}
