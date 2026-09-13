package zapmeta

import "strings"

// CustomTaxonomy holds static taxonomy overrides for custom/internal ZAP rule plugin IDs
// that are not in the standard ZAP alerts catalogue.
type CustomTaxonomy struct {
	CWEID      int
	CWEURI     string
	CAPECIDs   []int
	ATTACK     []string
	OWASPTop10 []string
}

// CanonicalPluginID returns a source-agnostic key for metadata lookup. It does
// not change the plugin ID stored on a definition, finding, or occurrence.
// Matching is case-insensitive and accepts the legacy source-prefixed form as
// well as the current custom-<source>-<slug> contract.
func CanonicalPluginID(pluginID string) string {
	id := strings.ToLower(strings.TrimSpace(pluginID))
	if strings.HasPrefix(id, "custom-") {
		id = strings.TrimPrefix(id, "custom-")
	}
	for _, prefix := range []string{"zap-", "nuclei-", "burp-"} {
		if strings.HasPrefix(id, prefix) {
			id = strings.TrimPrefix(id, prefix)
			break
		}
	}
	if alias, ok := customTaxonomyAliases[id]; ok {
		return alias
	}
	return id
}

// customTaxonomyAliases connects historical rule names to the current stable
// slugs. These are lookup aliases only; identity fields remain untouched.
var customTaxonomyAliases = map[string]string{
	"authenticated-basket-item-enumeration":          "auth-basket-items-enumeration",
	"authenticated-basket-object-reference-exposure": "auth-basket-object-reference",
	"authenticated-complaints-exposure":              "auth-complaints-exposure",
	"authenticated-user-directory-exposure":          "auth-user-directory-exposure",
}

var idorTaxonomy = CustomTaxonomy{
	CWEID:      639,
	CWEURI:     "https://cwe.mitre.org/data/definitions/639.html",
	CAPECIDs:   []int{122},
	OWASPTop10: []string{"A01:2021-Broken Access Control"},
	// ATT&CK is intentionally unresolved. T1078 describes obtaining or abusing
	// account credentials; these detectors establish object authorization
	// bypass with an authenticated test session, not credential compromise.
}

// customTaxonomyMap maps canonical custom-rule slugs to curated taxonomy. Only
// the object-reference detector controls a record key and therefore meets the
// CWE-639 mapping criteria. Collection-exposure rules remain unmapped until a
// more specific weakness is justified by their detector condition.
var customTaxonomyMap = map[string]CustomTaxonomy{
	"auth-basket-object-reference": idorTaxonomy,
}

// LookupCustomTaxonomy returns the static taxonomy for a plugin ID, or nil if not found.
func LookupCustomTaxonomy(pluginID string) *CustomTaxonomy {
	t, ok := customTaxonomyMap[CanonicalPluginID(pluginID)]
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
	g, ok := falsePositiveMap[CanonicalPluginID(pluginID)]
	if !ok {
		return nil
	}
	return &g
}
