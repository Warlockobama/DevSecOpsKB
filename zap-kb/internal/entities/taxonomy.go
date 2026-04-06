package entities

import (
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

// cweToOWASP maps CWE IDs to OWASP Top 10 2021 categories.
var cweToOWASP = map[int]string{
	22:  "A01:2021",
	79:  "A03:2021",
	89:  "A03:2021",
	200: "A05:2021",
	209: "A05:2021",
	287: "A07:2021",
	312: "A02:2021",
	319: "A02:2021",
	327: "A02:2021",
	502: "A08:2021",
	639: "A01:2021",
	693: "A05:2021",
	918: "A10:2021",
	942: "A05:2021",
}

// CWEToOWASP returns the OWASP Top 10 2021 category for a CWE ID, or "" if not mapped.
func CWEToOWASP(cweID int) string {
	return cweToOWASP[cweID]
}

// EnrichTaxonomy populates missing CWE and OWASP taxonomy fields on definitions.
// It is best-effort and never overwrites existing non-zero values.
// CWE is looked up from the zapmeta static map when not already set.
// OWASPTop10 is derived from cweToOWASP when not already set.
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

		// If we now have a CWE ID but no OWASP category, derive it.
		if d.Taxonomy != nil && d.Taxonomy.CWEID > 0 && len(d.Taxonomy.OWASPTop10) == 0 {
			if cat := cweToOWASP[d.Taxonomy.CWEID]; cat != "" {
				d.Taxonomy.OWASPTop10 = []string{cat}
			}
		}
	}
}
