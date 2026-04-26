package entities

import (
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

func TestEnrichCustomTaxonomy_AuthenticatedRule_GetsIDOR(t *testing.T) {
	defs := []Definition{
		{
			DefinitionID: "def-auth-basket",
			PluginID:     "zap-authenticated-basket-item-enumeration",
		},
	}
	EnrichCustomTaxonomy(defs)
	d := defs[0]
	if d.Taxonomy == nil {
		t.Fatal("expected Taxonomy to be set after EnrichCustomTaxonomy")
	}
	if d.Taxonomy.CWEID != 639 {
		t.Errorf("CWEID = %d, want 639", d.Taxonomy.CWEID)
	}
	if len(d.Taxonomy.OWASPTop10) == 0 || d.Taxonomy.OWASPTop10[0] != "A01:2021-Broken Access Control" {
		t.Errorf("OWASPTop10 = %v, want [A01:2021-Broken Access Control]", d.Taxonomy.OWASPTop10)
	}
}
