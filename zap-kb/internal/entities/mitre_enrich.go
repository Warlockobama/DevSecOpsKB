package entities

import (
	"fmt"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

// EnrichMITRE expands existing CWE, CAPEC, and ATT&CK identifiers with
// MITRE-maintained titles, canonical URLs, source attribution, and mapping
// confidence. It is offline and best-effort; it never overwrites analyst data.
func EnrichMITRE(defs []Definition) {
	for i := range defs {
		d := &defs[i]
		if d.Taxonomy == nil {
			continue
		}
		t := d.Taxonomy

		if t.CWEID > 0 {
			if ref := zapmeta.LookupCWEInfo(t.CWEID); ref != nil {
				if strings.TrimSpace(t.CWEName) == "" {
					t.CWEName = ref.Name
				}
				if strings.TrimSpace(t.CWEURI) == "" {
					t.CWEURI = ref.URL
				}
				addTaxonomySource(t, TaxonomySource{Name: ref.Source, URL: ref.URL})
			}
		}

		for _, id := range t.CAPECIDs {
			if ref := zapmeta.LookupCAPECInfo(id); ref != nil {
				upsertTaxonomyRef(&t.CAPEC, TaxonomyRef{ID: ref.ID, Name: ref.Name, URL: ref.URL})
				addTaxonomySource(t, TaxonomySource{Name: ref.Source, URL: ref.URL})
			}
		}

		for _, id := range t.ATTACK {
			if ref := zapmeta.LookupATTACKInfo(id); ref != nil {
				upsertTaxonomyRef(&t.ATTACKTechniques, TaxonomyRef{ID: ref.ID, Name: ref.Name, URL: ref.URL})
				addTaxonomySource(t, TaxonomySource{Name: ref.Source, URL: ref.URL})
			}
		}

		if strings.TrimSpace(t.MappingConfidence) == "" {
			switch {
			case len(t.ATTACK) > 0:
				t.MappingConfidence = "curated"
			case len(t.CAPECIDs) > 0:
				t.MappingConfidence = "curated-cwe-derived"
			case t.CWEID > 0:
				t.MappingConfidence = "scanner-cwe"
			}
		}
	}
}

// EnrichCVSS estimates definition-level CVSS when no official score is present.
// Scanner findings are weakness-based rather than CVE-based, so this intentionally
// records the source and rationale as estimated.
func EnrichCVSS(ef *EntitiesFile) {
	if ef == nil {
		return
	}
	maxRiskByDef := map[string]int{}
	riskSeenByDef := map[string]bool{}
	for _, f := range ef.Findings {
		rank, ok := riskRank(f.Risk, f.RiskCode)
		if !ok {
			continue
		}
		if !riskSeenByDef[f.DefinitionID] || rank > maxRiskByDef[f.DefinitionID] {
			maxRiskByDef[f.DefinitionID] = rank
		}
		riskSeenByDef[f.DefinitionID] = true
	}
	for _, o := range ef.Occurrences {
		rank, ok := riskRank(o.Risk, o.RiskCode)
		if !ok {
			continue
		}
		if !riskSeenByDef[o.DefinitionID] || rank > maxRiskByDef[o.DefinitionID] {
			maxRiskByDef[o.DefinitionID] = rank
		}
		riskSeenByDef[o.DefinitionID] = true
	}

	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		if d.CVSS != nil || !riskSeenByDef[d.DefinitionID] {
			continue
		}
		d.CVSS = estimatedCVSS(maxRiskByDef[d.DefinitionID])
	}
}

func upsertTaxonomyRef(refs *[]TaxonomyRef, ref TaxonomyRef) {
	id := strings.ToUpper(strings.TrimSpace(ref.ID))
	if id == "" {
		return
	}
	for i := range *refs {
		if strings.EqualFold(strings.TrimSpace((*refs)[i].ID), id) {
			if strings.TrimSpace((*refs)[i].Name) == "" {
				(*refs)[i].Name = ref.Name
			}
			if strings.TrimSpace((*refs)[i].URL) == "" {
				(*refs)[i].URL = ref.URL
			}
			return
		}
	}
	ref.ID = id
	*refs = append(*refs, ref)
}

func addTaxonomySource(t *Taxonomy, src TaxonomySource) {
	if t == nil || strings.TrimSpace(src.Name) == "" {
		return
	}
	src.Name = strings.TrimSpace(src.Name)
	src.URL = strings.TrimSpace(src.URL)
	src.Version = strings.TrimSpace(src.Version)
	for _, existing := range t.Sources {
		if strings.EqualFold(strings.TrimSpace(existing.Name), src.Name) &&
			strings.EqualFold(strings.TrimSpace(existing.URL), src.URL) {
			return
		}
	}
	t.Sources = append(t.Sources, src)
}

func riskRank(risk, riskCode string) (int, bool) {
	r := strings.ToLower(strings.TrimSpace(risk))
	if r == "" {
		r = strings.ToLower(strings.TrimSpace(riskCode))
	}
	switch r {
	case "3", "high":
		return 3, true
	case "2", "medium":
		return 2, true
	case "1", "low":
		return 1, true
	case "0", "info", "informational":
		return 0, true
	default:
		return 0, false
	}
}

func estimatedCVSS(rank int) *CVSS {
	cvss := &CVSS{
		Version:   "3.1",
		Source:    "devsecopskb-estimated",
		Rationale: "Estimated from scanner risk because this finding is weakness-based, not CVE-based.",
	}
	switch rank {
	case 3:
		cvss.Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
		cvss.BaseScore = 8.2
		cvss.BaseSeverity = "HIGH"
	case 2:
		cvss.Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
		cvss.BaseScore = 6.1
		cvss.BaseSeverity = "MEDIUM"
	case 1:
		cvss.Vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
		cvss.BaseScore = 3.1
		cvss.BaseSeverity = "LOW"
	default:
		cvss.Vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"
		cvss.BaseSeverity = "NONE"
	}
	if cvss.BaseScore > 0 {
		cvss.BaseSeverity = strings.ToUpper(cvss.BaseSeverity)
	} else if strings.TrimSpace(cvss.BaseSeverity) == "" {
		cvss.BaseSeverity = fmt.Sprintf("RANK-%d", rank)
	}
	return cvss
}
