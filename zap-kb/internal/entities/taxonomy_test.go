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

func TestEnrichTaxonomy_RemapsDeprecatedCWE264(t *testing.T) {
	// Plugin 10098 (Cross-Domain Misconfiguration) historically reports the
	// deprecated CWE-264 with the ill-fitting CAPEC-122. Enrichment must rewrite
	// it to the canonical CWE-942 and re-derive A05:2021 + CAPEC-1.
	defs := []Definition{
		{
			DefinitionID: "def-10098",
			PluginID:     "10098",
			Taxonomy: &Taxonomy{
				CWEID:      264,
				OWASPTop10: []string{"A05:2021"},
				CAPECIDs:   []int{122},
			},
		},
	}
	EnrichTaxonomy(defs)
	d := defs[0]
	if d.Taxonomy.CWEID != 942 {
		t.Errorf("CWEID = %d, want 942 (canonical replacement for deprecated 264)", d.Taxonomy.CWEID)
	}
	if len(d.Taxonomy.OWASPTop10) != 1 || d.Taxonomy.OWASPTop10[0] != "A05:2021" {
		t.Errorf("OWASPTop10 = %v, want [A05:2021]", d.Taxonomy.OWASPTop10)
	}
	if len(d.Taxonomy.CAPECIDs) != 1 || d.Taxonomy.CAPECIDs[0] != 1 {
		t.Errorf("CAPECIDs = %v, want [1] (CAPEC-1, not the deprecated CAPEC-122)", d.Taxonomy.CAPECIDs)
	}
	if d.Taxonomy.CWEURI != "https://cwe.mitre.org/data/definitions/942.html" {
		t.Errorf("CWEURI = %q, want canonical 942 URI", d.Taxonomy.CWEURI)
	}
}

func TestCWEToCAPEC_DeprecatedPillarDropped(t *testing.T) {
	// CWE-264 is deprecated and must not derive a CAPEC; it is remapped instead.
	if got := CWEToCAPEC(264); got != "" {
		t.Errorf("CWEToCAPEC(264) = %q, want empty (deprecated, remapped to 942)", got)
	}
	if got := CWEToOWASP(264); got != "" {
		t.Errorf("CWEToOWASP(264) = %q, want empty (deprecated, remapped to 942)", got)
	}
}

func TestEnrichCustomTaxonomy_HSTSAndReferrerGetTaxonomy(t *testing.T) {
	defs := []Definition{
		{DefinitionID: "def-hsts", PluginID: "nuclei-missing-hsts-header"},
		{DefinitionID: "def-referrer", PluginID: "zap-missing-referrer-policy"},
	}
	EnrichCustomTaxonomy(defs)
	if defs[0].Taxonomy == nil || defs[0].Taxonomy.CWEID != 319 ||
		len(defs[0].Taxonomy.OWASPTop10) == 0 || defs[0].Taxonomy.OWASPTop10[0] != "A02:2021" {
		t.Errorf("HSTS taxonomy = %+v, want CWE-319 / A02:2021", defs[0].Taxonomy)
	}
	if defs[1].Taxonomy == nil || defs[1].Taxonomy.CWEID != 200 ||
		len(defs[1].Taxonomy.OWASPTop10) == 0 || defs[1].Taxonomy.OWASPTop10[0] != "A05:2021" {
		t.Errorf("Referrer taxonomy = %+v, want CWE-200 / A05:2021", defs[1].Taxonomy)
	}
}

func TestEnrichCustomTaxonomy_JWTOWASPOverridesScannerA05(t *testing.T) {
	// The JWT password-hash finding is a cryptographic failure (A02:2021); the
	// curated OWASP must override a scanner-supplied A05:2021.
	defs := []Definition{
		{
			DefinitionID: "def-jwt",
			PluginID:     "zap-jwt-password-hash-disclosure",
			Taxonomy:     &Taxonomy{CWEID: 522, OWASPTop10: []string{"A05:2021"}},
		},
	}
	EnrichCustomTaxonomy(defs)
	d := defs[0]
	if len(d.Taxonomy.OWASPTop10) != 1 || d.Taxonomy.OWASPTop10[0] != "A02:2021" {
		t.Errorf("OWASPTop10 = %v, want [A02:2021]", d.Taxonomy.OWASPTop10)
	}
	// Curated CWE-522 is authoritative and overrides the scanner's CWE-200.
	if d.Taxonomy.CWEID != 522 {
		t.Errorf("CWEID = %d, want 522 (curated, overrides scanner CWE-200)", d.Taxonomy.CWEID)
	}
}

func TestEnrichCustomTaxonomy_CuratedCWEOverridesScanner_IDOR(t *testing.T) {
	// An IDOR finding the scanner mislabeled CWE-200/A05 must become the curated
	// CWE-639/A01 (the round-trip consistency case), using a real prefixed ID.
	// Stale CAPEC-118 + resolved ref simulate a JSON round-trip of the old
	// (wrong) CWE-200 derivation; both must be replaced by the curated CAPEC-122.
	defs := []Definition{{
		DefinitionID: "def-complaints",
		PluginID:     "nuclei-auth-complaints-exposure",
		Taxonomy: &Taxonomy{
			CWEID:      200,
			OWASPTop10: []string{"A05:2021"},
			CAPECIDs:   []int{118},
			CAPEC:      []TaxonomyRef{{ID: "CAPEC-118", Name: "Data Leakage Attacks"}},
		},
	}}
	EnrichCustomTaxonomy(defs)
	d := defs[0]
	if d.Taxonomy.CWEID != 639 {
		t.Errorf("CWEID = %d, want 639 (curated overrides scanner 200)", d.Taxonomy.CWEID)
	}
	if len(d.Taxonomy.OWASPTop10) != 1 || d.Taxonomy.OWASPTop10[0] != "A01:2021-Broken Access Control" {
		t.Errorf("OWASPTop10 = %v, want [A01:2021-Broken Access Control]", d.Taxonomy.OWASPTop10)
	}
	if len(d.Taxonomy.CAPECIDs) != 1 || d.Taxonomy.CAPECIDs[0] != 122 {
		t.Errorf("CAPECIDs = %v, want [122] (curated replaces stale 118)", d.Taxonomy.CAPECIDs)
	}
	if len(d.Taxonomy.CAPEC) != 0 {
		t.Errorf("CAPEC refs = %+v, want cleared so EnrichMITRE rebuilds them", d.Taxonomy.CAPEC)
	}
}

func TestEnrichCustomTaxonomy_BlanksUnmappedCustomRule(t *testing.T) {
	// A custom rule with no curated mapping must have the scanner's placeholder
	// CWE blanked (→ "Taxonomy incomplete"), not published.
	defs := []Definition{{
		DefinitionID: "def-new",
		PluginID:     "custom-nuclei-some-brand-new-rule",
		Taxonomy:     &Taxonomy{CWEID: 200, CWEURI: "x", OWASPTop10: []string{"A05:2021"}, CAPECIDs: []int{118}},
	}}
	EnrichCustomTaxonomy(defs)
	tx := defs[0].Taxonomy
	if tx.CWEID != 0 || len(tx.OWASPTop10) != 0 || len(tx.CAPECIDs) != 0 {
		t.Errorf("unmapped custom taxonomy not blanked: %+v", tx)
	}
}

func TestEnrichCustomTaxonomy_DoesNotBlankToolPlugin(t *testing.T) {
	// A standard numeric ZAP plugin is a trusted tool plugin: its scanner CWE
	// must be preserved even though it is not in customTaxonomyMap.
	defs := []Definition{{
		DefinitionID: "def-tool",
		PluginID:     "zap-10096", // Timestamp Disclosure, not a custom rule
		Taxonomy:     &Taxonomy{CWEID: 200, OWASPTop10: []string{"A05:2021"}},
	}}
	EnrichCustomTaxonomy(defs)
	if defs[0].Taxonomy.CWEID != 200 {
		t.Errorf("tool plugin taxonomy was blanked: %+v", defs[0].Taxonomy)
	}
}

func TestUnmappedCustomRules(t *testing.T) {
	defs := []Definition{
		{DefinitionID: "d1", PluginID: "nuclei-auth-complaints-exposure"}, // mapped
		{DefinitionID: "d2", PluginID: "zap-10098"},                       // tool, ignored
		{DefinitionID: "d3", PluginID: "custom-nuclei-brand-new-rule"},    // unmapped custom
		{DefinitionID: "d4", PluginID: "nuclei-brand-new-rule"},           // same canonical → deduped
	}
	got := UnmappedCustomRules(defs)
	if len(got) != 2 {
		t.Fatalf("UnmappedCustomRules = %v, want the two brand-new-rule ids", got)
	}
}

func TestEnrichCustomTaxonomy_CuratedCoversLiveCustomRules(t *testing.T) {
	// Every custom rule visible in the live KB must resolve to curated taxonomy
	// (no regressions to "incomplete"), using real source-prefixed IDs.
	cases := []struct {
		pid   string
		cwe   int
		owasp string
	}{
		{"nuclei-wildcard-cors-origin", 942, "A05:2021"},
		{"zap-missing-csp", 693, "A05:2021"},
		{"zap-sql-error-based-injection", 89, "A03:2021"},
		{"nuclei-public-application-configuration", 200, "A05:2021"},
		{"zap-stacktrace-disclosure", 209, "A05:2021"},
		{"nuclei-legacy-ftp-surface", 552, "A01:2021-Broken Access Control"},
	}
	for _, c := range cases {
		defs := []Definition{{DefinitionID: "d", PluginID: c.pid}}
		EnrichCustomTaxonomy(defs)
		tx := defs[0].Taxonomy
		if tx == nil || tx.CWEID != c.cwe || len(tx.OWASPTop10) == 0 || tx.OWASPTop10[0] != c.owasp {
			t.Errorf("%s → %+v, want CWE-%d / %s", c.pid, tx, c.cwe, c.owasp)
		}
	}
}

func TestCWEToCAPEC_CSPMapsToXSS(t *testing.T) {
	// CWE-693 (protection mechanism failure / missing CSP) should map to the XSS
	// attack pattern, not the ACL-bypass CAPEC-1.
	if got := CWEToCAPEC(693); got != "CAPEC-63" {
		t.Errorf("CWEToCAPEC(693) = %q, want CAPEC-63 (XSS)", got)
	}
}

// TestPublishPipeline_FlaggedFindings exercises the full enrichment order used
// by the export/publish path (custom → taxonomy → MITRE) over the four findings
// the SME flagged, asserting the final taxonomy that sinks render.
func TestPublishPipeline_FlaggedFindings(t *testing.T) {
	defs := []Definition{
		// CDM/CORS arriving with deprecated CWE-264 + ill-fitting CAPEC-122.
		// Real published pluginId is source-prefixed ("zap-10098"), which misses
		// the numeric cweFallback and exercises the static deprecation fallback.
		{DefinitionID: "def-10098", PluginID: "zap-10098", Alert: "Cross-Domain Misconfiguration",
			Taxonomy: &Taxonomy{CWEID: 264, OWASPTop10: []string{"A05:2021"}, CAPECIDs: []int{122}}},
		// FTP surface arriving with CWE-552 but no resolvable name.
		{DefinitionID: "def-ftp", PluginID: "nuclei-legacy-ftp-surface", Alert: "Legacy FTP Surface Exposed Over Web",
			Taxonomy: &Taxonomy{CWEID: 552}},
		// JWT password-hash arriving with the scanner's generic CWE-200 / A05.
		{DefinitionID: "def-jwt", PluginID: "zap-jwt-password-hash-disclosure", Alert: "JWT Token Contains Password Hash",
			Taxonomy: &Taxonomy{CWEID: 200, OWASPTop10: []string{"A05:2021"}}},
		// Custom header rules arriving with no taxonomy at all.
		{DefinitionID: "def-hsts", PluginID: "nuclei-missing-hsts-header", Alert: "Missing HSTS Header"},
		{DefinitionID: "def-ref", PluginID: "nuclei-missing-referrer-policy", Alert: "Missing Referrer-Policy Header"},
	}

	// Mirror the cmd/zap-kb export order.
	EnrichCustomTaxonomy(defs)
	EnrichTaxonomy(defs)
	EnrichMITRE(defs)

	byID := map[string]*Definition{}
	for i := range defs {
		byID[defs[i].DefinitionID] = &defs[i]
	}

	// 1. CDM: deprecated 264 rewritten to 942 → A05 + CAPEC-1, named.
	cdm := byID["def-10098"].Taxonomy
	if cdm.CWEID != 942 || cdm.CWEName != "Permissive Cross-domain Policy with Untrusted Domains" {
		t.Errorf("CDM CWE = %d %q, want 942 with resolved name", cdm.CWEID, cdm.CWEName)
	}
	if len(cdm.CAPECIDs) != 1 || cdm.CAPECIDs[0] != 1 {
		t.Errorf("CDM CAPEC = %v, want [1]", cdm.CAPECIDs)
	}
	if len(cdm.OWASPTop10) != 1 || cdm.OWASPTop10[0] != "A05:2021" {
		t.Errorf("CDM OWASP = %v, want [A05:2021]", cdm.OWASPTop10)
	}

	// 2. FTP: CWE-552 resolves to a real title (no "CWE-552: CWE-552").
	if n := byID["def-ftp"].Taxonomy.CWEName; n != "Files or Directories Accessible to External Parties" {
		t.Errorf("FTP CWEName = %q, want resolved title", n)
	}

	// 3. JWT: scanner CWE-200/A05 corrected to curated CWE-522/A02.
	if jwt := byID["def-jwt"].Taxonomy; jwt.CWEID != 522 || len(jwt.OWASPTop10) != 1 || jwt.OWASPTop10[0] != "A02:2021" {
		t.Errorf("JWT taxonomy = %+v, want CWE-522 / A02:2021", byID["def-jwt"].Taxonomy)
	}

	// 4. HSTS + Referrer: taxonomy now populated.
	if h := byID["def-hsts"].Taxonomy; h == nil || h.CWEID != 319 || len(h.OWASPTop10) == 0 || h.OWASPTop10[0] != "A02:2021" {
		t.Errorf("HSTS taxonomy = %+v, want CWE-319 / A02:2021", byID["def-hsts"].Taxonomy)
	}
	if r := byID["def-ref"].Taxonomy; r == nil || r.CWEID != 200 || len(r.OWASPTop10) == 0 || r.OWASPTop10[0] != "A05:2021" {
		t.Errorf("Referrer taxonomy = %+v, want CWE-200 / A05:2021", byID["def-ref"].Taxonomy)
	}
}

func TestEnrichCustomTaxonomy_AuthenticatedRule_GetsIDOR(t *testing.T) {
	// Real pipeline IDs are source-prefixed ("zap-"/"nuclei-"); both must resolve
	// to the same canonical IDOR taxonomy.
	for _, pid := range []string{
		"zap-auth-basket-items-enumeration",
		"nuclei-auth-basket-items-enumeration",
	} {
		defs := []Definition{{DefinitionID: "def-auth-basket", PluginID: pid}}
		EnrichCustomTaxonomy(defs)
		d := defs[0]
		if d.Taxonomy == nil {
			t.Fatalf("%s: expected Taxonomy to be set after EnrichCustomTaxonomy", pid)
		}
		if d.Taxonomy.CWEID != 639 {
			t.Errorf("%s: CWEID = %d, want 639", pid, d.Taxonomy.CWEID)
		}
		if len(d.Taxonomy.OWASPTop10) == 0 || d.Taxonomy.OWASPTop10[0] != "A01:2021-Broken Access Control" {
			t.Errorf("%s: OWASPTop10 = %v, want [A01:2021-Broken Access Control]", pid, d.Taxonomy.OWASPTop10)
		}
	}
}
