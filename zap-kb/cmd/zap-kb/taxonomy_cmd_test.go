package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestBuildTaxonomyAuditCountsCoverage(t *testing.T) {
	ef := entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-full",
				PluginID:     "10098",
				Alert:        "Cross-Domain Misconfiguration",
				Taxonomy: &entities.Taxonomy{
					CWEID:            942,
					OWASPTop10:       []string{"A05:2021"},
					CAPECIDs:         []int{1},
					ATTACKTechniques: []entities.TaxonomyRef{{ID: "T1190"}},
				},
			},
			{
				DefinitionID: "def-partial",
				PluginID:     "10038",
				Taxonomy:     &entities.Taxonomy{CWEID: 693},
			},
		},
	}

	got := buildTaxonomyAudit(ef)
	if got.Definitions != 2 || got.CWE != 2 || got.OWASP != 1 || got.CAPEC != 1 || got.ATTACK != 1 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if len(got.Missing) != 1 || got.Missing[0].DefinitionID != "def-partial" {
		t.Fatalf("missing rows = %+v, want def-partial only", got.Missing)
	}
}

func TestParseCWEWeaknesses(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Name="CWE" Version="4.20" Date="2026-04-30" xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="942" Name="Permissive Cross-domain Policy with Untrusted Domains" Status="Draft">
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="346"/>
      </Related_Weaknesses>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>`)

	version, date, weaknesses, err := parseCWEWeaknesses(raw)
	if err != nil {
		t.Fatalf("parseCWEWeaknesses: %v", err)
	}
	if version != "4.20" || date != "2026-04-30" {
		t.Fatalf("version/date = %q/%q", version, date)
	}
	if len(weaknesses) != 1 {
		t.Fatalf("weaknesses = %+v, want one", weaknesses)
	}
	w := weaknesses[0]
	if w.ID != 942 || w.Name != "Permissive Cross-domain Policy with Untrusted Domains" || w.Status != "Draft" {
		t.Fatalf("unexpected CWE weakness: %+v", w)
	}
	if w.URL != "https://cwe.mitre.org/data/definitions/942.html" {
		t.Fatalf("URL = %q", w.URL)
	}
	if len(w.RelatedWeaknesses) != 1 || w.RelatedWeaknesses[0] != 346 {
		t.Fatalf("RelatedWeaknesses = %+v", w.RelatedWeaknesses)
	}
}

func TestParseCAPECAttackPatterns(t *testing.T) {
	raw := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Name="CAPEC" Version="3.9" Date="2023-01-24">
  <Attack_Patterns>
    <Attack_Pattern ID="1" Name="Accessing Functionality Not Properly Constrained by ACLs" Status="Draft">
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="276"/>
        <Related_Weakness CWE_ID="285"/>
      </Related_Weaknesses>
      <External_References>
        <External_Reference External_ID="T1190"/>
      </External_References>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>`)

	version, date, patterns, err := parseCAPECAttackPatterns(raw)
	if err != nil {
		t.Fatalf("parseCAPECAttackPatterns: %v", err)
	}
	if version != "3.9" || date != "2023-01-24" {
		t.Fatalf("version/date = %q/%q", version, date)
	}
	if len(patterns) != 1 {
		t.Fatalf("patterns = %+v, want one", patterns)
	}
	p := patterns[0]
	if p.ID != 1 || p.Name != "Accessing Functionality Not Properly Constrained by ACLs" || p.Status != "Draft" {
		t.Fatalf("unexpected CAPEC pattern: %+v", p)
	}
	if p.URL != "https://capec.mitre.org/data/definitions/1.html" {
		t.Fatalf("URL = %q", p.URL)
	}
	if len(p.RelatedWeaknesses) != 2 || p.RelatedWeaknesses[0] != 276 || p.RelatedWeaknesses[1] != 285 {
		t.Fatalf("RelatedWeaknesses = %+v", p.RelatedWeaknesses)
	}
	if len(p.RelatedATTACKIDs) != 1 || p.RelatedATTACKIDs[0] != "T1190" {
		t.Fatalf("RelatedATTACKIDs = %+v", p.RelatedATTACKIDs)
	}
}

func TestFetchCWECacheFromZip(t *testing.T) {
	xmlData := []byte(`<Weakness_Catalog Version="4.20" Date="2026-04-30"><Weaknesses><Weakness ID="79" Name="XSS" Status="Stable"/></Weaknesses></Weakness_Catalog>`)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("cwe.xml")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := f.Write(xmlData); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	cache, err := fetchCWECache(srv.URL + "/download")
	if err != nil {
		t.Fatalf("fetchCWECache: %v", err)
	}
	if cache.Schema != "devsecopskb/cwe-cache/v1" || cache.Version != "4.20" {
		t.Fatalf("bad cache metadata: %+v", cache)
	}
	if len(cache.Weaknesses) != 1 || cache.Weaknesses[0].ID != 79 {
		t.Fatalf("bad weaknesses: %+v", cache.Weaknesses)
	}
}

func TestIsZipPayload(t *testing.T) {
	if !isZipPayload([]byte{'P', 'K', 0x03, 0x04, 'x'}) {
		t.Fatal("expected ZIP magic header to be detected")
	}
	if !isZipPayload([]byte{'P', 'K', 0x05, 0x06}) {
		t.Fatal("expected empty ZIP archive signature to be detected")
	}
	if isZipPayload([]byte("<xml></xml>")) {
		t.Fatal("did not expect XML to be detected as ZIP")
	}
}

func TestFetchURLBytesErrorsWhenLimitExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("123456"))
	}))
	defer srv.Close()

	_, err := fetchURLBytes(srv.URL, "text/plain", 5)
	if err == nil {
		t.Fatal("expected size limit error")
	}
	if got := err.Error(); got != "GET "+srv.URL+": response exceeded size limit of 5 bytes" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchCAPECCacheFromXML(t *testing.T) {
	xmlData := []byte(`<Attack_Pattern_Catalog Version="3.9" Date="2023-01-24"><Attack_Patterns><Attack_Pattern ID="66" Name="SQL Injection" Status="Stable"/></Attack_Patterns></Attack_Pattern_Catalog>`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(xmlData)
	}))
	defer srv.Close()

	cache, err := fetchCAPECCache(srv.URL)
	if err != nil {
		t.Fatalf("fetchCAPECCache: %v", err)
	}
	if cache.Schema != "devsecopskb/capec-cache/v1" || cache.Version != "3.9" {
		t.Fatalf("bad cache metadata: %+v", cache)
	}
	if len(cache.AttackPatterns) != 1 || cache.AttackPatterns[0].ID != 66 {
		t.Fatalf("bad attack patterns: %+v", cache.AttackPatterns)
	}
}

func TestBuildCAPECCandidatesUsesOfficialRelatedWeaknesses(t *testing.T) {
	ef := entities.EntitiesFile{
		Definitions: []entities.Definition{
			{
				DefinitionID: "def-cors",
				PluginID:     "10098",
				Alert:        "Cross-Domain Misconfiguration",
				Taxonomy:     &entities.Taxonomy{CWEID: 942},
			},
			{
				DefinitionID: "def-empty",
				PluginID:     "99999",
				Taxonomy:     &entities.Taxonomy{CWEID: 99999},
			},
		},
	}
	cache := capecCache{
		AttackPatterns: []capecAttackPattern{
			{ID: 1, Name: "Accessing Functionality Not Properly Constrained by ACLs", URL: "https://capec.mitre.org/data/definitions/1.html", RelatedWeaknesses: []int{942}},
			{ID: 122, Name: "Privilege Abuse", URL: "https://capec.mitre.org/data/definitions/122.html", RelatedWeaknesses: []int{639, 942}},
		},
	}

	rows := buildCAPECCandidates(ef, cache)
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want one", rows)
	}
	if rows[0].DefinitionID != "def-cors" || rows[0].CWEID != 942 {
		t.Fatalf("unexpected row: %+v", rows[0])
	}
	if len(rows[0].Candidates) != 2 || rows[0].Candidates[0].ID != 1 || rows[0].Candidates[1].ID != 122 {
		t.Fatalf("candidates = %+v", rows[0].Candidates)
	}
}

func TestParseAttackTechniquesSkipsDeprecatedAndSorts(t *testing.T) {
	raw := []byte(`{
	  "type": "bundle",
	  "objects": [
	    {
	      "type": "attack-pattern",
	      "name": "Valid Accounts",
	      "external_references": [{"source_name":"mitre-attack","external_id":"T1078","url":"https://attack.mitre.org/techniques/T1078/"}],
	      "kill_chain_phases": [{"kill_chain_name":"mitre-attack","phase_name":"defense-evasion"},{"kill_chain_name":"mitre-attack","phase_name":"persistence"}]
	    },
	    {
	      "type": "attack-pattern",
	      "name": "Deprecated",
	      "x_mitre_deprecated": true,
	      "external_references": [{"source_name":"mitre-attack","external_id":"T0000"}]
	    },
	    {
	      "type": "malware",
	      "name": "Ignore me"
	    }
	  ]
	}`)

	got, err := parseAttackTechniques(raw)
	if err != nil {
		t.Fatalf("parseAttackTechniques: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("techniques = %+v, want one", got)
	}
	if got[0].ID != "T1078" || got[0].Name != "Valid Accounts" {
		t.Fatalf("unexpected technique: %+v", got[0])
	}
	if len(got[0].Tactics) != 2 || got[0].Tactics[0] != "defense-evasion" || got[0].Tactics[1] != "persistence" {
		t.Fatalf("tactics = %+v", got[0].Tactics)
	}
}

func TestFetchAttackTechniqueCacheWritesSourceMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "objects": [{
		    "type":"attack-pattern",
		    "name":"Exploit Public-Facing Application",
		    "external_references":[{"source_name":"mitre-attack","external_id":"T1190","url":"https://attack.mitre.org/techniques/T1190/"}]
		  }]
		}`))
	}))
	defer srv.Close()

	cache, err := fetchAttackTechniqueCache(srv.URL)
	if err != nil {
		t.Fatalf("fetchAttackTechniqueCache: %v", err)
	}
	if cache.Schema != "devsecopskb/attack-technique-cache/v1" || cache.SourceURL != srv.URL {
		t.Fatalf("bad cache metadata: %+v", cache)
	}
	if len(cache.Techniques) != 1 || cache.Techniques[0].ID != "T1190" {
		t.Fatalf("bad techniques: %+v", cache.Techniques)
	}

	out := filepath.Join(t.TempDir(), "attack.json")
	if err := writeJSONFile(out, cache); err != nil {
		t.Fatalf("writeJSONFile: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var decoded attackTechniqueCache
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode written cache: %v", err)
	}
	if len(decoded.Techniques) != 1 || decoded.Techniques[0].ID != "T1190" {
		t.Fatalf("decoded cache = %+v", decoded)
	}
}
