package zapmeta

import "testing"

// TestLookupFalsePositiveGuidance_HighVolumeRulesHave2PlusScenarios enforces
// the #41 acceptance criterion: CDM (10098), CSP (10038), and CDJSF (10017)
// each carry at least two FP scenarios so analysts can rapidly distinguish
// noise from real issues on the highest-volume rule families.
func TestLookupFalsePositiveGuidance_HighVolumeRulesHave2PlusScenarios(t *testing.T) {
	for _, plugin := range []string{"10098", "10038", "10017"} {
		g := LookupFalsePositiveGuidance(plugin)
		if g == nil {
			t.Errorf("plugin %s: expected FP guidance entry, got nil", plugin)
			continue
		}
		if len(g.Conditions) < 2 {
			t.Errorf("plugin %s: expected >=2 FP scenarios, got %d", plugin, len(g.Conditions))
		}
	}
}

func TestLookupFalsePositiveGuidance_UnknownPluginReturnsNil(t *testing.T) {
	if g := LookupFalsePositiveGuidance("99999"); g != nil {
		t.Errorf("unknown plugin should return nil, got %+v", g)
	}
}
