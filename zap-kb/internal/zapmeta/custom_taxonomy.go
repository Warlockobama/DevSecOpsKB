package zapmeta

import (
	"strconv"
	"strings"
)

// CustomTaxonomy holds static taxonomy overrides for custom/internal ZAP rule plugin IDs
// that are not in the standard ZAP alerts catalogue.
type CustomTaxonomy struct {
	CWEID      int
	CWEURI     string
	CAPECIDs   []int
	ATTACK     []string
	OWASPTop10 []string
}

// knownSourcePrefixes are the scanner/source tokens the devsecopskb pipeline
// prepends to every imported rule identifier (e.g. "zap-10098",
// "nuclei-missing-hsts-header", "zap-missing-referrer-policy"). The same logical
// rule is imported once per source tool, so these prefixes are stripped before
// any taxonomy lookup — otherwise a curated entry would have to enumerate every
// source variant and would silently miss new ones.
var knownSourcePrefixes = []string{"zap-", "nuclei-", "burp-"}

// CanonicalPluginID returns the source-agnostic lookup key for a plugin ID. It
// trims an optional "custom-" marker (the pipeline tags KB-authored rules
// "custom-nuclei-…"/"custom-zap-…") and then one known source prefix:
//
//	"zap-10098"                          → "10098"   (ZAP numeric plugin)
//	"custom-nuclei-missing-hsts-header"  → "missing-hsts-header"
//	"custom-zap-jwt-password-hash-disclosure" → "jwt-password-hash-disclosure"
//	"nuclei-missing-referrer-policy"     → "missing-referrer-policy"
//	"missing-hsts-header"                → "missing-hsts-header" (already canonical)
//
// Matching is case-insensitive; one "custom-" and one source prefix are removed.
func CanonicalPluginID(pluginID string) string {
	id := strings.TrimSpace(pluginID)
	if strings.HasPrefix(strings.ToLower(id), "custom-") {
		id = id[len("custom-"):]
	}
	lower := strings.ToLower(id)
	for _, p := range knownSourcePrefixes {
		if strings.HasPrefix(lower, p) {
			return id[len(p):]
		}
	}
	return id
}

func cweURI(id int) string {
	return "https://cwe.mitre.org/data/definitions/" + strconv.Itoa(id) + ".html"
}

// Shared mappings for custom-rule families.
var (
	// IDOR / broken access control (the authenticated-access rules).
	idorTaxonomy = CustomTaxonomy{
		CWEID: 639, CWEURI: cweURI(639), CAPECIDs: []int{122},
		ATTACK: []string{"T1078"}, OWASPTop10: []string{"A01:2021-Broken Access Control"},
	}
	// Sensitive information exposed to unauthenticated callers.
	infoExposureTaxonomy = CustomTaxonomy{
		CWEID: 200, CWEURI: cweURI(200), CAPECIDs: []int{118}, OWASPTop10: []string{"A05:2021"},
	}
	// Error/stack-trace responses leaking internal detail.
	errorDisclosureTaxonomy = CustomTaxonomy{
		CWEID: 209, CWEURI: cweURI(209), CAPECIDs: []int{118}, OWASPTop10: []string{"A05:2021"},
	}
)

// customTaxonomyMap maps the CANONICAL (prefix-stripped) plugin ID of a custom /
// KB-authored rule to its static taxonomy. Keys are the source-agnostic slug the
// pipeline emits after the "custom-"/"zap-"/"nuclei-" prefixes — see
// CanonicalPluginID. Because custom rules are KB-owned, every custom rule the KB
// publishes MUST appear here: an unmapped custom rule is deliberately left with
// blank taxonomy ("Taxonomy incomplete") rather than inheriting the scanner's
// generic placeholder CWE. The export prints a diagnostic listing any custom
// rule that lands here without a mapping.
var customTaxonomyMap = map[string]CustomTaxonomy{
	// --- Access control (IDOR) ---
	"auth-basket-items-enumeration": idorTaxonomy,
	"auth-basket-object-reference":  idorTaxonomy,
	"auth-complaints-exposure":      idorTaxonomy,
	"auth-user-directory-exposure":  idorTaxonomy,

	// --- Unauthenticated information exposure ---
	"public-application-configuration": infoExposureTaxonomy,
	"public-challenge-metadata":        infoExposureTaxonomy,
	"public-feedback-exposure":         infoExposureTaxonomy,
	"robots-sensitive-paths":           infoExposureTaxonomy,

	// --- Error / stack-trace disclosure ---
	"captcha-route-error-disclosure": errorDisclosureTaxonomy,
	"stacktrace-disclosure":          errorDisclosureTaxonomy,

	// --- Response-header hardening ---
	// HSTS absent → cleartext transmission exposure.
	"missing-hsts-header": {CWEID: 319, CWEURI: cweURI(319), OWASPTop10: []string{"A02:2021"}},
	// Referrer-Policy absent → sensitive information disclosure via Referer.
	"missing-referrer-policy": {CWEID: 200, CWEURI: cweURI(200), OWASPTop10: []string{"A05:2021"}},
	// CSP absent → protection-mechanism failure enabling client-side injection.
	"missing-csp": {CWEID: 693, CWEURI: cweURI(693), CAPECIDs: []int{63}, OWASPTop10: []string{"A05:2021"}},
	// Permissive CORS (wildcard origin).
	"wildcard-cors-origin": {CWEID: 942, CWEURI: cweURI(942), CAPECIDs: []int{1}, OWASPTop10: []string{"A05:2021"}},

	// --- Other KB-authored rules ---
	// Legacy FTP content reachable over the web root.
	"legacy-ftp-surface": {CWEID: 552, CWEURI: cweURI(552), OWASPTop10: []string{"A01:2021-Broken Access Control"}},
	// Error-based SQL injection.
	"sql-error-based-injection": {CWEID: 89, CWEURI: cweURI(89), CAPECIDs: []int{66}, OWASPTop10: []string{"A03:2021"}},
	// Credential hash embedded in a token → cryptographic failure. CWE-522 is the
	// precise weakness, more so than the scanner's generic CWE-200.
	"jwt-password-hash-disclosure": {CWEID: 522, CWEURI: cweURI(522), OWASPTop10: []string{"A02:2021"}},
}

// LookupCustomTaxonomy returns the static taxonomy for a plugin ID, or nil if not
// found. The ID is canonicalized so every source variant maps to one entry.
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

// LookupFalsePositiveGuidance returns FP conditions for a plugin ID, or nil if
// not found. The ID is canonicalized so source-prefixed IDs (e.g. "zap-10098")
// match the numeric falsePositiveMap keys.
func LookupFalsePositiveGuidance(pluginID string) *FalsePositiveGuidance {
	g, ok := falsePositiveMap[CanonicalPluginID(pluginID)]
	if !ok {
		return nil
	}
	return &g
}
