package entities

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	cweCacheSchema    = "devsecopskb/cwe-cache/v1"
	capecCacheSchema  = "devsecopskb/capec-cache/v1"
	attackCacheSchema = "devsecopskb/attack-technique-cache/v1"
)

// MITRECachePaths points at local JSON caches written by `zap-kb taxonomy update`.
// Empty paths are ignored, preserving the built-in offline fallback tables.
type MITRECachePaths struct {
	CWE    string
	CAPEC  string
	ATTACK string
}

// MITRECatalogs stores local official-catalog metadata for runtime enrichment.
// It intentionally carries only display metadata; mapping decisions still come
// from scanner IDs or curated KB mappings.
type MITRECatalogs struct {
	cwe    map[int]mitreCatalogRef
	capec  map[int]mitreCatalogRef
	attack map[string]mitreCatalogRef
}

type mitreCatalogRef struct {
	ID        string
	Name      string
	URL       string
	Source    string
	SourceURL string
	Version   string
}

// LoadMITRECatalogs reads any supplied local official-catalog caches.
func LoadMITRECatalogs(paths MITRECachePaths) (*MITRECatalogs, error) {
	catalogs := &MITRECatalogs{}
	if path := strings.TrimSpace(paths.CWE); path != "" {
		refs, err := readCWECacheCatalog(path)
		if err != nil {
			return nil, fmt.Errorf("read CWE cache %q: %w", path, err)
		}
		catalogs.cwe = refs
	}
	if path := strings.TrimSpace(paths.CAPEC); path != "" {
		refs, err := readCAPECCacheCatalog(path)
		if err != nil {
			return nil, fmt.Errorf("read CAPEC cache %q: %w", path, err)
		}
		catalogs.capec = refs
	}
	if path := strings.TrimSpace(paths.ATTACK); path != "" {
		refs, err := readATTACKCacheCatalog(path)
		if err != nil {
			return nil, fmt.Errorf("read ATT&CK cache %q: %w", path, err)
		}
		catalogs.attack = refs
	}
	return catalogs, nil
}

func readCWECacheCatalog(path string) (map[int]mitreCatalogRef, error) {
	var cache struct {
		Schema      string `json:"schema"`
		SourceURL   string `json:"sourceUrl"`
		GeneratedAt string `json:"generatedAt"`
		Version     string `json:"version"`
		Weaknesses  []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"weaknesses"`
	}
	if err := readCatalogJSON(path, cweCacheSchema, &cache); err != nil {
		return nil, err
	}
	refs := make(map[int]mitreCatalogRef, len(cache.Weaknesses))
	for _, item := range cache.Weaknesses {
		if item.ID <= 0 {
			continue
		}
		refs[item.ID] = mitreCatalogRef{
			ID:        fmt.Sprintf("CWE-%d", item.ID),
			Name:      strings.TrimSpace(item.Name),
			URL:       strings.TrimSpace(item.URL),
			Source:    "MITRE CWE",
			SourceURL: firstNonEmptyString(cache.SourceURL, item.URL),
			Version:   strings.TrimSpace(cache.Version),
		}
	}
	return refs, nil
}

func readCAPECCacheCatalog(path string) (map[int]mitreCatalogRef, error) {
	var cache struct {
		Schema         string `json:"schema"`
		SourceURL      string `json:"sourceUrl"`
		GeneratedAt    string `json:"generatedAt"`
		Version        string `json:"version"`
		AttackPatterns []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"attackPatterns"`
	}
	if err := readCatalogJSON(path, capecCacheSchema, &cache); err != nil {
		return nil, err
	}
	refs := make(map[int]mitreCatalogRef, len(cache.AttackPatterns))
	for _, item := range cache.AttackPatterns {
		if item.ID <= 0 {
			continue
		}
		refs[item.ID] = mitreCatalogRef{
			ID:        fmt.Sprintf("CAPEC-%d", item.ID),
			Name:      strings.TrimSpace(item.Name),
			URL:       strings.TrimSpace(item.URL),
			Source:    "MITRE CAPEC",
			SourceURL: firstNonEmptyString(cache.SourceURL, item.URL),
			Version:   strings.TrimSpace(cache.Version),
		}
	}
	return refs, nil
}

func readATTACKCacheCatalog(path string) (map[string]mitreCatalogRef, error) {
	var cache struct {
		Schema      string `json:"schema"`
		SourceURL   string `json:"sourceUrl"`
		GeneratedAt string `json:"generatedAt"`
		Techniques  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"techniques"`
	}
	if err := readCatalogJSON(path, attackCacheSchema, &cache); err != nil {
		return nil, err
	}
	refs := make(map[string]mitreCatalogRef, len(cache.Techniques))
	for _, item := range cache.Techniques {
		id := strings.ToUpper(strings.TrimSpace(item.ID))
		if id == "" {
			continue
		}
		refs[id] = mitreCatalogRef{
			ID:        id,
			Name:      strings.TrimSpace(item.Name),
			URL:       strings.TrimSpace(item.URL),
			Source:    "MITRE ATT&CK",
			SourceURL: firstNonEmptyString(cache.SourceURL, item.URL),
			Version:   strings.TrimSpace(cache.GeneratedAt),
		}
	}
	return refs, nil
}

func readCatalogJSON(path, expectedSchema string, out any) error {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return err
	}
	if strings.TrimSpace(expectedSchema) != "" {
		var envelope struct {
			Schema string `json:"schema"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return err
		}
		if strings.TrimSpace(envelope.Schema) != expectedSchema {
			return fmt.Errorf("unexpected schema %q, want %q", envelope.Schema, expectedSchema)
		}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return err
	}
	return nil
}
