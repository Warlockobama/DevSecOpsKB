package zapmeta

// CustomTaxonomy holds static taxonomy overrides for custom/internal ZAP rule plugin IDs
// that are not in the standard ZAP alerts catalogue.
type CustomTaxonomy struct {
	CWEID      int
	CWEURI     string
	CAPECIDs   []int
	ATTACK     []string
	OWASPTop10 []string
}

// customTaxonomyMap maps plugin IDs to their static taxonomy.
// The 4 authenticated-* rules are custom IDOR/access-control findings.
var customTaxonomyMap = map[string]CustomTaxonomy{
	"zap-authenticated-basket-item-enumeration": {
		CWEID:      639,
		CWEURI:     "https://cwe.mitre.org/data/definitions/639.html",
		CAPECIDs:   []int{122},
		ATTACK:     []string{"T1078"},
		OWASPTop10: []string{"A01:2021-Broken Access Control"},
	},
	"zap-authenticated-basket-object-reference-exposure": {
		CWEID:      639,
		CWEURI:     "https://cwe.mitre.org/data/definitions/639.html",
		CAPECIDs:   []int{122},
		ATTACK:     []string{"T1078"},
		OWASPTop10: []string{"A01:2021-Broken Access Control"},
	},
	"zap-authenticated-complaints-exposure": {
		CWEID:      639,
		CWEURI:     "https://cwe.mitre.org/data/definitions/639.html",
		CAPECIDs:   []int{122},
		ATTACK:     []string{"T1078"},
		OWASPTop10: []string{"A01:2021-Broken Access Control"},
	},
	"zap-authenticated-user-directory-exposure": {
		CWEID:      639,
		CWEURI:     "https://cwe.mitre.org/data/definitions/639.html",
		CAPECIDs:   []int{122},
		ATTACK:     []string{"T1078"},
		OWASPTop10: []string{"A01:2021-Broken Access Control"},
	},
}

// LookupCustomTaxonomy returns the static taxonomy for a plugin ID, or nil if not found.
func LookupCustomTaxonomy(pluginID string) *CustomTaxonomy {
	t, ok := customTaxonomyMap[pluginID]
	if !ok {
		return nil
	}
	return &t
}

// FalsePositiveGuidance holds false positive conditions for a plugin ID.
type FalsePositiveGuidance struct {
	Conditions []string
}

// falsePositiveMap maps well-known plugin IDs to their FP guidance.
var falsePositiveMap = map[string]FalsePositiveGuidance{
	"10098": { // Cross-Domain Misconfiguration (CDM)
		Conditions: []string{
			"Access-Control-Allow-Origin: * on public CDN endpoints or unauthenticated static assets is expected behavior.",
			"Third-party widgets (analytics, fonts, payment iframes) legitimately require cross-domain access.",
			"Flag only when authenticated endpoints return permissive CORS headers.",
		},
	},
	"10038": { // Content Security Policy (CSP) Header Not Set
		Conditions: []string{
			"Legacy pages served from a CMS that does not support CSP injection may flag here; verify at the CDN or reverse proxy layer.",
			"CSP delivered via meta tag rather than HTTP header will not be detected by this rule.",
		},
	},
	"10017": { // Cross-Domain JavaScript Source File Inclusion (CDJSF)
		Conditions: []string{
			"Third-party analytics and tag manager scripts (Google Analytics, GTM, Segment) are expected findings on most web apps.",
			"Scripts loaded from owned CDN subdomains are not cross-domain risks.",
		},
	},
}

// LookupFalsePositiveGuidance returns FP conditions for a plugin ID, or nil if not found.
func LookupFalsePositiveGuidance(pluginID string) *FalsePositiveGuidance {
	g, ok := falsePositiveMap[pluginID]
	if !ok {
		return nil
	}
	return &g
}
