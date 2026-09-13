package entities

import (
	"reflect"
	"testing"
)

func TestCWEToOWASP(t *testing.T) {
	cases := []struct {
		cwe  int
		want string
	}{
		{79, "A03:2021"},
		{89, "A03:2021"},
		{22, "A01:2021"},
		{200, "A05:2021"},
		{287, "A07:2021"},
		{312, "A02:2021"},
		{319, "A02:2021"},
		{502, "A08:2021"},
		{639, "A01:2021"},
		{693, "A05:2021"},
		{918, "A10:2021"},
		{942, "A05:2021"},
		{209, "A05:2021"},
		{327, "A02:2021"},
		{9999, ""}, // unmapped
		{0, ""},    // zero value
	}
	for _, tc := range cases {
		got := CWEToOWASP(tc.cwe)
		if got != tc.want {
			t.Errorf("CWEToOWASP(%d) = %q, want %q", tc.cwe, got, tc.want)
		}
	}
}

func TestEnrichTaxonomy_FromZapMeta(t *testing.T) {
	// Plugin 40014 = SQL Injection = CWE-89 in zapmeta cweFallback
	defs := []Definition{
		{DefinitionID: "def-40014", PluginID: "40014"},
	}
	EnrichTaxonomy(defs)
	d := defs[0]
	if d.Taxonomy == nil {
		t.Fatal("expected Taxonomy to be set")
	}
	if d.Taxonomy.CWEID != 89 {
		t.Errorf("CWEID = %d, want 89", d.Taxonomy.CWEID)
	}
	if len(d.Taxonomy.OWASPTop10) == 0 || d.Taxonomy.OWASPTop10[0] != "A03:2021" {
		t.Errorf("OWASPTop10 = %v, want [A03:2021]", d.Taxonomy.OWASPTop10)
	}
}

func TestEnrichTaxonomy_DoesNotOverwrite(t *testing.T) {
	// Existing CWE and OWASP values must not be overwritten.
	defs := []Definition{
		{
			DefinitionID: "def-40014",
			PluginID:     "40014",
			Taxonomy: &Taxonomy{
				CWEID:      1234,
				OWASPTop10: []string{"A99:2021"},
			},
		},
	}
	EnrichTaxonomy(defs)
	d := defs[0]
	if d.Taxonomy.CWEID != 1234 {
		t.Errorf("CWEID overwritten: got %d, want 1234", d.Taxonomy.CWEID)
	}
	if len(d.Taxonomy.OWASPTop10) != 1 || d.Taxonomy.OWASPTop10[0] != "A99:2021" {
		t.Errorf("OWASPTop10 overwritten: got %v", d.Taxonomy.OWASPTop10)
	}
}

func TestEnrichTaxonomy_UnknownPlugin(t *testing.T) {
	// Plugin not in zapmeta static map — taxonomy should remain nil.
	defs := []Definition{
		{DefinitionID: "def-99999", PluginID: "99999"},
	}
	EnrichTaxonomy(defs)
	if defs[0].Taxonomy != nil {
		t.Errorf("expected Taxonomy to remain nil for unknown plugin, got %+v", defs[0].Taxonomy)
	}
}

func TestEnrichTaxonomy_HasCWEButNoOWASP(t *testing.T) {
	// Taxonomy already has CWE but OWASPTop10 is empty — should be filled.
	defs := []Definition{
		{
			DefinitionID: "def-x",
			PluginID:     "99999",
			Taxonomy:     &Taxonomy{CWEID: 79},
		},
	}
	EnrichTaxonomy(defs)
	if len(defs[0].Taxonomy.OWASPTop10) == 0 || defs[0].Taxonomy.OWASPTop10[0] != "A03:2021" {
		t.Errorf("OWASPTop10 = %v, want [A03:2021]", defs[0].Taxonomy.OWASPTop10)
	}
}

func TestCWEToCAPEC_SQLInjection(t *testing.T) {
	got := CWEToCAPEC(89)
	if got != "CAPEC-66" {
		t.Errorf("CWEToCAPEC(89) = %q, want %q", got, "CAPEC-66")
	}
}

func TestCWEToCAPEC_Unknown(t *testing.T) {
	got := CWEToCAPEC(9999)
	if got != "" {
		t.Errorf("CWEToCAPEC(9999) = %q, want empty string", got)
	}
}

func TestEnrichTaxonomy_PopulatesCAPEC(t *testing.T) {
	// Plugin 40014 = SQL Injection = CWE-89 = CAPEC-66
	defs := []Definition{
		{DefinitionID: "def-sql", PluginID: "40014"},
	}
	EnrichTaxonomy(defs)
	d := defs[0]
	if d.Taxonomy == nil {
		t.Fatal("expected Taxonomy to be set")
	}
	if d.Taxonomy.CWEID != 89 {
		t.Errorf("CWEID = %d, want 89", d.Taxonomy.CWEID)
	}
	if len(d.Taxonomy.CAPECIDs) == 0 || d.Taxonomy.CAPECIDs[0] != 66 {
		t.Errorf("CAPECIDs = %v, want [66]", d.Taxonomy.CAPECIDs)
	}
}

func TestEnrichCustomTaxonomy_BasketItemsRuleIsExplicitlyUnmapped(t *testing.T) {
	defs := []Definition{
		{
			DefinitionID: "def-auth-basket",
			PluginID:     "zap-authenticated-basket-item-enumeration",
		},
	}
	EnrichCustomTaxonomy(defs)
	d := defs[0]
	if d.Taxonomy == nil {
		t.Fatal("expected taxonomy gap marker after EnrichCustomTaxonomy")
	}
	if d.Taxonomy.CWEID != 0 {
		t.Errorf("CWEID = %d, want unresolved", d.Taxonomy.CWEID)
	}
	if !reflect.DeepEqual(d.Taxonomy.Tags, []string{"taxonomy-unmapped-custom"}) {
		t.Errorf("taxonomy tags = %v, want mapping gap", d.Taxonomy.Tags)
	}
}

func TestEnrichCustomTaxonomy_AliasPrecedenceAndIdentity(t *testing.T) {
	for _, pluginID := range []string{
		"zap-authenticated-basket-object-reference-exposure",
		"zap-auth-basket-object-reference",
		"nuclei-auth-basket-object-reference",
		"custom-zap-auth-basket-object-reference",
	} {
		t.Run(pluginID, func(t *testing.T) {
			defs := []Definition{{
				DefinitionID: "def-stable",
				PluginID:     pluginID,
				Origin:       DefinitionOriginCustom,
				Taxonomy: &Taxonomy{
					CWEID:             200,
					CWEName:           "Exposure of Sensitive Information",
					CWEURI:            "https://cwe.mitre.org/data/definitions/200.html",
					CAPECIDs:          []int{118},
					CAPEC:             []TaxonomyRef{{ID: "CAPEC-118"}},
					OWASPTop10:        []string{"A05:2021"},
					MappingConfidence: "scanner-cwe",
				},
				Detection: &Detection{MatchReason: "portable synthetic detector trace"},
			}}

			EnrichCustomTaxonomy(defs)
			EnrichTaxonomy(defs)
			EnrichMITRE(defs)

			got := defs[0]
			if got.DefinitionID != "def-stable" || got.PluginID != pluginID {
				t.Fatalf("identity changed: definition=%q plugin=%q", got.DefinitionID, got.PluginID)
			}
			if got.Detection == nil || got.Detection.MatchReason != "portable synthetic detector trace" {
				t.Fatalf("detection trace changed: %+v", got.Detection)
			}
			if got.Taxonomy.CWEID != 639 || got.Taxonomy.CWEName != "Authorization Bypass Through User-Controlled Key" {
				t.Fatalf("taxonomy = %+v, want curated CWE-639", got.Taxonomy)
			}
			if len(got.Taxonomy.CAPECIDs) != 1 || got.Taxonomy.CAPECIDs[0] != 122 {
				t.Fatalf("CAPEC IDs = %v, want [122]", got.Taxonomy.CAPECIDs)
			}
			if len(got.Taxonomy.OWASPTop10) != 1 || got.Taxonomy.OWASPTop10[0] != "A01:2021-Broken Access Control" {
				t.Fatalf("OWASP = %v", got.Taxonomy.OWASPTop10)
			}
			if got.Taxonomy.MappingConfidence != "curated" || len(got.Taxonomy.Sources) < 2 {
				t.Fatalf("taxonomy attribution = %+v", got.Taxonomy)
			}
			if len(got.Taxonomy.ATTACK) != 0 {
				t.Fatalf("ATT&CK must remain unresolved for object authorization bypass, got %v", got.Taxonomy.ATTACK)
			}

			first := *got.Taxonomy
			EnrichCustomTaxonomy(defs)
			EnrichTaxonomy(defs)
			EnrichMITRE(defs)
			if !reflect.DeepEqual(first, *defs[0].Taxonomy) {
				t.Fatalf("repeat enrichment changed taxonomy:\nfirst=%+v\nsecond=%+v", first, *defs[0].Taxonomy)
			}
		})
	}
}

func TestEnrichCustomTaxonomy_PreservesImportedTaxonomyWithoutKnownProvenance(t *testing.T) {
	for _, confidence := range []string{"", "high", "analyst-reviewed", "advisory-reviewed"} {
		t.Run("confidence="+confidence, func(t *testing.T) {
			want := &Taxonomy{
				CWEID:             284,
				CWEName:           "Improper Access Control",
				CWEURI:            "https://cwe.mitre.org/data/definitions/284.html",
				CAPECIDs:          []int{1},
				ATTACK:            []string{"T1190"},
				OWASPTop10:        []string{"A01:2021"},
				MappingConfidence: confidence,
				Sources:           []TaxonomySource{{Name: "Analyst advisory", URL: "https://example.invalid/advisory"}},
			}
			defs := []Definition{{
				DefinitionID: "def-reviewed",
				PluginID:     "custom-nuclei-auth-basket-object-reference",
				Origin:       DefinitionOriginCustom,
				Taxonomy:     want,
			}}
			before := *want
			EnrichCustomTaxonomy(defs)
			if !reflect.DeepEqual(before, *defs[0].Taxonomy) {
				t.Fatalf("imported taxonomy changed:\nbefore=%+v\nafter=%+v", before, *defs[0].Taxonomy)
			}
		})
	}
}

func TestEnrichCustomTaxonomy_UnmappedCustomIsExplicitlyIncomplete(t *testing.T) {
	defs := []Definition{{
		DefinitionID: "def-unmapped",
		PluginID:     "custom-nuclei-new-unreviewed-rule",
		Origin:       DefinitionOriginCustom,
		Taxonomy: &Taxonomy{
			CWEID:             200,
			OWASPTop10:        []string{"A05:2021"},
			MappingConfidence: "scanner-cwe",
			Tags:              []string{"portable-fixture"},
		},
	}}
	EnrichCustomTaxonomy(defs)
	got := defs[0].Taxonomy
	if got.CWEID != 200 || len(got.OWASPTop10) != 1 || got.MappingConfidence != "scanner-cwe" {
		t.Fatalf("unmapped custom taxonomy was destructively changed: %+v", got)
	}
	if !reflect.DeepEqual(got.Tags, []string{"portable-fixture", "taxonomy-unmapped-custom"}) {
		t.Fatalf("taxonomy gap tag = %v", got.Tags)
	}
	if gaps := UnmappedCustomRules(defs); !reflect.DeepEqual(gaps, []string{"custom-nuclei-new-unreviewed-rule"}) {
		t.Fatalf("UnmappedCustomRules = %v", gaps)
	}
}

func TestEnrichCustomTaxonomy_RemovesOnlyLegacyCuratedT1078(t *testing.T) {
	defs := []Definition{
		{
			DefinitionID: "def-generated",
			PluginID:     "custom-zap-auth-basket-object-reference",
			Origin:       DefinitionOriginCustom,
			Taxonomy: &Taxonomy{
				CWEID:             639,
				ATTACK:            []string{"T1078"},
				ATTACKTechniques:  []TaxonomyRef{{ID: "T1078"}},
				MappingConfidence: "curated",
				Sources:           []TaxonomySource{{Name: "MITRE CWE"}, {Name: "MITRE ATT&CK"}},
			},
		},
		{
			DefinitionID: "def-owned",
			PluginID:     "custom-zap-auth-basket-object-reference",
			Origin:       DefinitionOriginCustom,
			Taxonomy: &Taxonomy{
				CWEID:             639,
				ATTACK:            []string{"T1078"},
				MappingConfidence: "high",
			},
		},
	}
	EnrichCustomTaxonomy(defs)
	if len(defs[0].Taxonomy.ATTACK) != 0 || len(defs[0].Taxonomy.ATTACKTechniques) != 0 {
		t.Fatalf("legacy generated ATT&CK mapping retained: %+v", defs[0].Taxonomy)
	}
	if len(defs[0].Taxonomy.Sources) != 1 || defs[0].Taxonomy.Sources[0].Name != "MITRE CWE" {
		t.Fatalf("legacy ATT&CK source migration = %+v", defs[0].Taxonomy.Sources)
	}
	if !reflect.DeepEqual(defs[1].Taxonomy.ATTACK, []string{"T1078"}) {
		t.Fatalf("imported ATT&CK mapping changed: %+v", defs[1].Taxonomy)
	}
}

func TestEnrichCustomTaxonomy_NativeRuleIsNeverReclassified(t *testing.T) {
	want := &Taxonomy{CWEID: 200, MappingConfidence: "scanner-cwe"}
	defs := []Definition{{
		DefinitionID: "def-native",
		PluginID:     "nuclei-auth-basket-items-enumeration",
		Origin:       DefinitionOriginTool,
		Taxonomy:     want,
	}}
	before := *want
	EnrichCustomTaxonomy(defs)
	if !reflect.DeepEqual(before, *defs[0].Taxonomy) {
		t.Fatalf("native taxonomy changed: before=%+v after=%+v", before, *defs[0].Taxonomy)
	}
}
