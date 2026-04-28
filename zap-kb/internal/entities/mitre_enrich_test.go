package entities

import "testing"

func TestEnrichMITREExpandsCWEAndCAPEC(t *testing.T) {
	defs := []Definition{
		{
			DefinitionID: "def-sql",
			Taxonomy: &Taxonomy{
				CWEID:    89,
				CAPECIDs: []int{66},
			},
		},
	}

	EnrichMITRE(defs)

	tax := defs[0].Taxonomy
	if tax.CWEName == "" {
		t.Fatal("expected CWEName to be populated")
	}
	if tax.CWEURI != "https://cwe.mitre.org/data/definitions/89.html" {
		t.Fatalf("CWEURI = %q", tax.CWEURI)
	}
	if len(tax.CAPEC) != 1 || tax.CAPEC[0].ID != "CAPEC-66" {
		t.Fatalf("CAPEC refs = %+v, want CAPEC-66", tax.CAPEC)
	}
	if tax.MappingConfidence != "curated-cwe-derived" {
		t.Fatalf("MappingConfidence = %q", tax.MappingConfidence)
	}
	if len(tax.Sources) == 0 {
		t.Fatal("expected MITRE sources to be recorded")
	}
}

func TestEnrichMITREExpandsATTACK(t *testing.T) {
	defs := []Definition{
		{
			DefinitionID: "def-custom",
			Taxonomy: &Taxonomy{
				ATTACK: []string{"T1078"},
			},
		},
	}

	EnrichMITRE(defs)

	techniques := defs[0].Taxonomy.ATTACKTechniques
	if len(techniques) != 1 {
		t.Fatalf("ATTACKTechniques = %+v, want one technique", techniques)
	}
	if techniques[0].Name != "Valid Accounts" {
		t.Fatalf("ATTACK technique name = %q", techniques[0].Name)
	}
	if techniques[0].URL != "https://attack.mitre.org/techniques/T1078/" {
		t.Fatalf("ATTACK technique URL = %q", techniques[0].URL)
	}
}

func TestEnrichMITREDoesNotOverwriteAnalystFields(t *testing.T) {
	defs := []Definition{
		{
			DefinitionID: "def-xss",
			Taxonomy: &Taxonomy{
				CWEID:             79,
				CWEName:           "Custom CWE title",
				MappingConfidence: "analyst-reviewed",
			},
		},
	}

	EnrichMITRE(defs)

	if defs[0].Taxonomy.CWEName != "Custom CWE title" {
		t.Fatalf("CWEName was overwritten: %q", defs[0].Taxonomy.CWEName)
	}
	if defs[0].Taxonomy.MappingConfidence != "analyst-reviewed" {
		t.Fatalf("MappingConfidence was overwritten: %q", defs[0].Taxonomy.MappingConfidence)
	}
}

func TestEnrichCVSSEstimatesFromMaxDefinitionRisk(t *testing.T) {
	ef := &EntitiesFile{
		Definitions: []Definition{{DefinitionID: "def-1"}},
		Findings: []Finding{
			{DefinitionID: "def-1", Risk: "Low"},
			{DefinitionID: "def-1", Risk: "Medium"},
		},
		Occurrences: []Occurrence{
			{DefinitionID: "def-1", Risk: "High"},
		},
	}

	EnrichCVSS(ef)

	cvss := ef.Definitions[0].CVSS
	if cvss == nil {
		t.Fatal("expected CVSS to be populated")
	}
	if cvss.BaseSeverity != "HIGH" || cvss.BaseScore != 8.2 {
		t.Fatalf("CVSS = %+v, want HIGH 8.2", cvss)
	}
	if cvss.Source != "devsecopskb-estimated" {
		t.Fatalf("CVSS source = %q", cvss.Source)
	}
}

func TestEnrichCVSSDoesNotOverwriteExisting(t *testing.T) {
	ef := &EntitiesFile{
		Definitions: []Definition{
			{
				DefinitionID: "def-1",
				CVSS:         &CVSS{Version: "3.1", BaseSeverity: "LOW", BaseScore: 3.1, Source: "analyst"},
			},
		},
		Findings: []Finding{{DefinitionID: "def-1", Risk: "High"}},
	}

	EnrichCVSS(ef)

	if ef.Definitions[0].CVSS.Source != "analyst" {
		t.Fatalf("existing CVSS was overwritten: %+v", ef.Definitions[0].CVSS)
	}
}

func TestEnrichCVSSLeavesDefinitionWithoutRiskAlone(t *testing.T) {
	ef := &EntitiesFile{
		Definitions: []Definition{{DefinitionID: "def-1"}},
	}

	EnrichCVSS(ef)

	if ef.Definitions[0].CVSS != nil {
		t.Fatalf("expected CVSS to remain nil, got %+v", ef.Definitions[0].CVSS)
	}
}
