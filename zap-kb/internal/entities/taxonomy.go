package entities

import (
	"fmt"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

// cweToOWASP maps CWE IDs to OWASP Top 10 2021 categories.
// CWE-264 is a deprecated umbrella; CWE-942 is the correct mapping for permissive CORS.
// CWE-264 is retained as a backwards-compat alias.
var cweToOWASP = map[int]string{
	22:  "A01:2021",
	79:  "A03:2021",
	89:  "A03:2021",
	200: "A05:2021",
	209: "A05:2021",
	264: "A05:2021", // deprecated alias for CWE-942 (Permissive Cross-domain Policy)
	287: "A07:2021",
	311: "A02:2021",
	312: "A02:2021",
	319: "A02:2021",
	327: "A02:2021",
	502: "A08:2021",
	639: "A01:2021",
	693: "A05:2021",
	918: "A10:2021",
	942: "A05:2021", // Permissive Cross-domain Policy with Untrusted Domains → A05:2021
}

// cweToCAPEC maps CWE IDs to CAPEC identifiers.
// Static map; covers the most common ZAP finding types.
var cweToCAPEC = map[int]string{
	79:  "CAPEC-86",  // XSS → Exploitation of Improper Data Validation
	89:  "CAPEC-66",  // SQL Injection
	200: "CAPEC-118", // Exposure of Sensitive Information
	264: "CAPEC-122", // deprecated CDM alias (Privilege Abuse)
	311: "CAPEC-37",  // Cleartext Storage
	639: "CAPEC-122", // IDOR / Authorization Through User-Controlled Key
	693: "CAPEC-1",   // Protection Mechanism Failure (CSP) → Accessing/Intercepting/Modifying HTTP Communication
	942: "CAPEC-1",   // Permissive CORS
}

// CWEToOWASP returns the OWASP Top 10 2021 category for a CWE ID, or "" if not mapped.
func CWEToOWASP(cweID int) string {
	return cweToOWASP[cweID]
}

// CWEToCAPEC returns the CAPEC identifier for a CWE ID, or "" if not mapped.
func CWEToCAPEC(cweID int) string {
	return cweToCAPEC[cweID]
}

// parseCAPECID extracts the numeric CAPEC ID from a string like "CAPEC-66".
// Returns 0 if the string is empty or does not match the expected format.
func parseCAPECID(s string) int {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToUpper(s), "CAPEC-") {
		return 0
	}
	numStr := s[len("CAPEC-"):]
	n := 0
	_, err := fmt.Sscanf(numStr, "%d", &n)
	if err != nil {
		return 0
	}
	return n
}

// EnrichTaxonomy populates missing CWE, OWASP, and CAPEC taxonomy fields on definitions.
// It is best-effort and never overwrites existing non-zero values.
// CWE is looked up from the zapmeta static map when not already set.
// OWASPTop10 is derived from cweToOWASP when not already set.
// CAPECIDs is derived from cweToCAPEC when not already set.
func EnrichTaxonomy(defs []Definition) {
	for i := range defs {
		d := &defs[i]

		// If taxonomy is absent or CWE is unknown, attempt lookup via zapmeta static map.
		if d.Taxonomy == nil || d.Taxonomy.CWEID == 0 {
			r := zapmeta.LookupPlugin(d.PluginID)
			if r != nil && r.CWEID > 0 {
				if d.Taxonomy == nil {
					d.Taxonomy = &Taxonomy{}
				}
				if d.Taxonomy.CWEID == 0 {
					d.Taxonomy.CWEID = r.CWEID
				}
				if d.Taxonomy.CWEURI == "" && r.CWEURI != "" {
					d.Taxonomy.CWEURI = r.CWEURI
				}
			}
		}

		if d.Taxonomy == nil || d.Taxonomy.CWEID == 0 {
			continue
		}

		// If we have a CWE ID but no OWASP category, derive it.
		if len(d.Taxonomy.OWASPTop10) == 0 {
			if cat := cweToOWASP[d.Taxonomy.CWEID]; cat != "" {
				d.Taxonomy.OWASPTop10 = []string{cat}
			}
		}

		// If we have a CWE ID but no CAPEC IDs, derive from static map.
		if len(d.Taxonomy.CAPECIDs) == 0 {
			if capec := cweToCAPEC[d.Taxonomy.CWEID]; capec != "" {
				if id := parseCAPECID(capec); id > 0 {
					d.Taxonomy.CAPECIDs = []int{id}
				}
			}
		}
	}
}
