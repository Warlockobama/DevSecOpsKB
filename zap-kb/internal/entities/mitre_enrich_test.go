package entities

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestEnrichMITREWithCatalogsUsesOfficialCacheMetadata(t *testing.T) {
	dir := t.TempDir()
	cwePath := filepath.Join(dir, "cwe-cache.json")
	capecPath := filepath.Join(dir, "capec-cache.json")
	attackPath := filepath.Join(dir, "attack-cache.json")
	writeTestFile(t, cwePath, `{
  "schema": "devsecopskb/cwe-cache/v1",
  "sourceUrl": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
  "version": "4.20",
  "weaknesses": [
    {"id": 89, "name": "Cache SQL Injection", "url": "https://cwe.mitre.org/data/definitions/89.html"}
  ]
}`)
	writeTestFile(t, capecPath, `{
  "schema": "devsecopskb/capec-cache/v1",
  "sourceUrl": "https://capec.mitre.org/data/xml/capec_latest.xml",
  "version": "3.9",
  "attackPatterns": [
    {"id": 66, "name": "Cache SQL Injection Pattern", "url": "https://capec.mitre.org/data/definitions/66.html"}
  ]
}`)
	writeTestFile(t, attackPath, `{
  "schema": "devsecopskb/attack-technique-cache/v1",
  "generatedAt": "2026-05-05T00:00:00Z",
  "sourceUrl": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
  "techniques": [
    {"id": "T1190", "name": "Cache Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"}
  ]
}`)
	catalogs, err := LoadMITRECatalogs(MITRECachePaths{
		CWE:    cwePath,
		CAPEC:  capecPath,
		ATTACK: attackPath,
	})
	if err != nil {
		t.Fatalf("LoadMITRECatalogs: %v", err)
	}
	defs := []Definition{
		{
			DefinitionID: "def-sql",
			Taxonomy: &Taxonomy{
				CWEID:    89,
				CAPECIDs: []int{66},
				ATTACK:   []string{"T1190"},
			},
		},
	}

	EnrichMITREWithCatalogs(defs, catalogs)

	tax := defs[0].Taxonomy
	if tax.CWEName != "Cache SQL Injection" {
		t.Fatalf("CWEName = %q", tax.CWEName)
	}
	if len(tax.CAPEC) != 1 || tax.CAPEC[0].Name != "Cache SQL Injection Pattern" {
		t.Fatalf("CAPEC refs = %+v", tax.CAPEC)
	}
	if len(tax.ATTACKTechniques) != 1 || tax.ATTACKTechniques[0].Name != "Cache Exploit Public-Facing Application" {
		t.Fatalf("ATTACKTechniques = %+v", tax.ATTACKTechniques)
	}
	if !hasTaxonomySourceVersion(tax.Sources, "MITRE CWE", "4.20") {
		t.Fatalf("sources missing MITRE CWE version: %+v", tax.Sources)
	}
	if !hasTaxonomySourceVersion(tax.Sources, "MITRE CAPEC", "3.9") {
		t.Fatalf("sources missing MITRE CAPEC version: %+v", tax.Sources)
	}
	if !hasTaxonomySourceVersion(tax.Sources, "MITRE ATT&CK", "2026-05-05T00:00:00Z") {
		t.Fatalf("sources missing MITRE ATT&CK cache timestamp: %+v", tax.Sources)
	}
}

func TestLoadMITRECatalogsRejectsWrongSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrong-cache.json")
	writeTestFile(t, path, `{
  "schema": "devsecopskb/capec-cache/v1",
  "attackPatterns": []
}`)

	_, err := LoadMITRECatalogs(MITRECachePaths{CWE: path})
	if err == nil {
		t.Fatal("expected wrong cache schema to fail")
	}
}

func TestAddTaxonomySourceUpgradesMissingVersion(t *testing.T) {
	tax := &Taxonomy{
		Sources: []TaxonomySource{{
			Name: "MITRE CWE",
			URL:  "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
		}},
	}

	addTaxonomySource(tax, TaxonomySource{
		Name:    "MITRE CWE",
		URL:     "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
		Version: "4.20",
	})

	if len(tax.Sources) != 1 {
		t.Fatalf("sources = %+v, want one deduplicated source", tax.Sources)
	}
	if tax.Sources[0].Version != "4.20" {
		t.Fatalf("source version = %q, want 4.20", tax.Sources[0].Version)
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

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func hasTaxonomySourceVersion(sources []TaxonomySource, name, version string) bool {
	for _, source := range sources {
		if source.Name == name && source.Version == version {
			return true
		}
	}
	return false
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
