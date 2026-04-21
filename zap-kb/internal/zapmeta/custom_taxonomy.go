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

// falsePositiveMap maps well-known plugin IDs to their FP guidance. Each entry
// must list 2+ benign scenarios so analysts can rapidly distinguish noise from
// true positives on the highest-volume rule families (#41).
var falsePositiveMap = map[string]FalsePositiveGuidance{
	"10098": { // Cross-Domain Misconfiguration (CDM)
		Conditions: []string{
			"Access-Control-Allow-Origin: * on public CDN endpoints or unauthenticated static assets (fonts, images, JS bundles) is expected behavior — these resources are designed to be publicly cacheable.",
			"Third-party widgets and SDKs (analytics, fonts.googleapis.com, payment iframes, Intercom/Zendesk) legitimately require permissive CORS headers on the resources they expose.",
			"Pre-flight OPTIONS responses on documented public APIs (e.g. /v1/public/*) are expected to advertise wildcard origins; confirm the matching GET/POST is also unauthenticated.",
			"True positive only when an authenticated endpoint (cookie- or token-protected) returns Access-Control-Allow-Origin: * — that combination breaks the same-origin policy and enables cross-site data theft.",
		},
	},
	"10038": { // Content Security Policy (CSP) Header Not Set
		Conditions: []string{
			"Legacy pages served from a CMS that does not support CSP injection often flag here; verify whether the header is added at the CDN or reverse proxy edge before opening a ticket.",
			"CSP delivered via <meta http-equiv=\"Content-Security-Policy\"> in the HTML head is not visible to ZAP's response-header check — view the page source to confirm.",
			"Static error pages, API-only responses (application/json without an HTML body), and downloadable file responses do not require CSP since no script context exists.",
			"True positive when a logged-in HTML application page returns no CSP header in either the response or upstream proxy — XSS protections degrade to legacy X-XSS-Protection only.",
		},
	},
	"10017": { // Cross-Domain JavaScript Source File Inclusion (CDJSF)
		Conditions: []string{
			"Third-party analytics, tag managers, and consent platforms (Google Analytics, GTM, Segment, OneTrust, Hotjar) are expected on most marketing and product pages.",
			"Scripts loaded from owned CDN subdomains (e.g. cdn.example.com from app.example.com) are first-party from a trust perspective and not real cross-domain risks.",
			"Embedded payment, video, or chat SDKs (Stripe.js, YouTube embed, Intercom widget) require cross-domain script tags by design.",
			"True positive when a script tag pulls executable JavaScript from an unexpected domain (typosquat, expired CDN, non-vendor host) — verify the integrity attribute and the vendor relationship before suppressing.",
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
