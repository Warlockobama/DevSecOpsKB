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
	EnrichMITREWithCatalogs(defs, nil)
}

// EnrichMITREWithCatalogs expands existing CWE, CAPEC, and ATT&CK identifiers
// using local official-catalog caches when provided, then falls back to the
// built-in curated metadata tables.
func EnrichMITREWithCatalogs(defs []Definition, catalogs *MITRECatalogs) {
	for i := range defs {
		d := &defs[i]
		if d.Taxonomy == nil {
			continue
		}
		t := d.Taxonomy

		if t.CWEID > 0 {
			if ref := lookupCWERef(catalogs, t.CWEID); ref != nil {
				if strings.TrimSpace(t.CWEName) == "" {
					t.CWEName = ref.Name
				}
				if strings.TrimSpace(t.CWEURI) == "" {
					t.CWEURI = ref.URL
				}
				addMITRECatalogSource(t, ref)
			}
		}

		for _, id := range t.CAPECIDs {
			if ref := lookupCAPECRef(catalogs, id); ref != nil {
				upsertTaxonomyRef(&t.CAPEC, TaxonomyRef{ID: ref.ID, Name: ref.Name, URL: ref.URL})
				addMITRECatalogSource(t, ref)
			}
		}

		for _, id := range t.ATTACK {
			if ref := lookupATTACKRef(catalogs, id); ref != nil {
				upsertTaxonomyRef(&t.ATTACKTechniques, TaxonomyRef{ID: ref.ID, Name: ref.Name, URL: ref.URL})
				addMITRECatalogSource(t, ref)
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

func lookupCWERef(catalogs *MITRECatalogs, id int) *mitreCatalogRef {
	if catalogs != nil && catalogs.cwe != nil {
		if ref, ok := catalogs.cwe[id]; ok {
			return &ref
		}
	}
	return catalogRefFromZapmeta(zapmeta.LookupCWEInfo(id), "")
}

func lookupCAPECRef(catalogs *MITRECatalogs, id int) *mitreCatalogRef {
	if catalogs != nil && catalogs.capec != nil {
		if ref, ok := catalogs.capec[id]; ok {
			return &ref
		}
	}
	return catalogRefFromZapmeta(zapmeta.LookupCAPECInfo(id), "")
}

func lookupATTACKRef(catalogs *MITRECatalogs, id string) *mitreCatalogRef {
	id = strings.ToUpper(strings.TrimSpace(id))
	if catalogs != nil && catalogs.attack != nil {
		if ref, ok := catalogs.attack[id]; ok {
			return &ref
		}
	}
	return catalogRefFromZapmeta(zapmeta.LookupATTACKInfo(id), "")
}

func catalogRefFromZapmeta(ref *zapmeta.MITRERef, version string) *mitreCatalogRef {
	if ref == nil {
		return nil
	}
	return &mitreCatalogRef{
		ID:        ref.ID,
		Name:      ref.Name,
		URL:       ref.URL,
		Source:    ref.Source,
		SourceURL: ref.URL,
		Version:   strings.TrimSpace(version),
	}
}

func addMITRECatalogSource(t *Taxonomy, ref *mitreCatalogRef) {
	if ref == nil {
		return
	}
	addTaxonomySource(t, TaxonomySource{Name: ref.Source, URL: firstNonEmptyString(ref.SourceURL, ref.URL), Version: ref.Version})
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
	for i := range t.Sources {
		if strings.EqualFold(strings.TrimSpace(t.Sources[i].Name), src.Name) &&
			strings.EqualFold(strings.TrimSpace(t.Sources[i].URL), src.URL) {
			if strings.TrimSpace(t.Sources[i].Version) == "" && src.Version != "" {
				t.Sources[i].Version = src.Version
			}
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
