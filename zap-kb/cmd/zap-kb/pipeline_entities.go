package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

type entityPipelineOptions struct {
	Format             string
	RunOut             string
	RunIn              string
	EntitiesIn         string
	GeneratedAt        string
	Source             string
	ScanLabel          string
	Plugins            string
	AllPlugins         bool
	InitMode           bool
	IncludeTraffic     bool
	TrafficScope       string
	TrafficMaxBytes    int
	TrafficMaxPerIssue int
	TrafficMinRisk     string
	TrafficTotalMax    int
	IncludeDetection   bool
	DetectionDetails   string
	IncludeMITRE       bool
	MITRECWECache      string
	MITRECAPECCache    string
	MITREATTACKCache   string
	IncludeCVSS        bool
	ZAPAlertsOnly      bool
	FetchAllowed       bool
	TriagePolicy       config.TriagePolicy
}

// buildPipelineEntities owns identity creation, merge policy, enrichment,
// normalization, and final graph validation. Renderers and sinks receive only
// its validated result.
func buildPipelineEntities(ctx, discoveryCtx context.Context, client *zapclient.Client, alerts []zapclient.Alert, input entities.EntitiesFile, opts entityPipelineOptions) (entities.EntitiesFile, string, error) {
	var ent entities.EntitiesFile
	if opts.Format != "entities" && opts.Format != "both" && opts.Format != "obsidian" && opts.RunOut == "" {
		return ent, opts.ScanLabel, nil
	}
	if strings.TrimSpace(opts.RunIn) != "" || strings.TrimSpace(opts.EntitiesIn) != "" {
		ent = input
	}
	runGeneratedAt := strings.TrimSpace(opts.GeneratedAt)
	if runGeneratedAt == "" {
		switch {
		case len(alerts) > 0:
			runGeneratedAt = time.Now().UTC().Format(time.RFC3339)
		case strings.TrimSpace(ent.GeneratedAt) != "":
			runGeneratedAt = ent.GeneratedAt
		default:
			runGeneratedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	scanLabel := opts.ScanLabel
	if strings.TrimSpace(scanLabel) == "" && len(alerts) > 0 {
		derived := fmt.Sprintf("%s-%s", strings.TrimSpace(strings.ToLower(opts.Source)), time.Now().UTC().Format("20060102-150405"))
		derived = strings.TrimPrefix(derived, "-")
		scanLabel = derived
		fmt.Fprintf(os.Stderr, "[warn] no -scan-label set; auto-derived %q for this run\n", derived)
		fmt.Fprintf(os.Stderr, "[warn] Tip: pass -scan-label=<env>-<YYYYMMDD> for reproducible runs (e.g. prod-%s)\n", time.Now().UTC().Format("20060102"))
	} else if strings.TrimSpace(scanLabel) == "" && (strings.TrimSpace(opts.RunIn) != "" || len(input.Occurrences) > 0) {
		fmt.Fprintln(os.Stderr, "[warn] no -scan-label set; occurrences from previous runs may not have a scan label")
	}
	if len(alerts) > 0 {
		built := entities.BuildEntitiesWithOptions(alerts, entities.BuildOptions{SourceTool: opts.Source, ScanLabel: scanLabel, GeneratedAt: runGeneratedAt, ObservedAt: runGeneratedAt})
		if len(ent.Definitions) == 0 && len(ent.Findings) == 0 && len(ent.Occurrences) == 0 {
			ent = built
		} else {
			ent = entities.MergeWithPolicy(ent, built, opts.TriagePolicy)
		}
	}

	newDefs := addRequestedDefinitions(discoveryCtx, &ent, opts)
	ent.GeneratedAt = runGeneratedAt
	if strings.TrimSpace(ent.SchemaVersion) == "" {
		ent.SchemaVersion = "v1"
	}
	if strings.TrimSpace(ent.SourceTool) == "" {
		ent.SourceTool = opts.Source
	}
	if strings.TrimSpace(ent.GeneratedAt) == "" {
		ent.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if opts.IncludeTraffic || opts.IncludeDetection {
		enrichCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if opts.IncludeTraffic {
			if opts.TrafficScope == "all" {
				_ = entities.EnrichAllTraffic(enrichCtx, client, &ent, opts.TrafficMaxBytes)
			} else {
				_ = entities.EnrichTrafficSelective(enrichCtx, client, &ent, opts.TrafficMaxPerIssue, opts.TrafficMinRisk, opts.TrafficTotalMax, opts.TrafficMaxBytes)
			}
		}
		if opts.IncludeDetection {
			entities.EnrichDetections(enrichCtx, &ent)
			if strings.EqualFold(strings.TrimSpace(opts.DetectionDetails), "summary") {
				entities.EnrichDetectionSummaries(enrichCtx, &ent)
			}
		}
	}

	entities.NormalizeDefinitionOrigins(&ent)
	entities.EnrichCustomTaxonomy(ent.Definitions)
	entities.EnrichTaxonomy(ent.Definitions)
	if opts.IncludeMITRE {
		catalogs, err := entities.LoadMITRECatalogs(entities.MITRECachePaths{CWE: opts.MITRECWECache, CAPEC: opts.MITRECAPECCache, ATTACK: opts.MITREATTACKCache})
		if err != nil {
			return ent, scanLabel, fmt.Errorf("load MITRE caches: operation failed (private details omitted)")
		}
		entities.EnrichMITREWithCatalogs(ent.Definitions, catalogs)
	}
	if opts.IncludeCVSS {
		entities.EnrichCVSS(&ent)
	}
	if opts.ZAPAlertsOnly {
		beforeDefs, beforeFindings, beforeOccurrences := len(ent.Definitions), len(ent.Findings), len(ent.Occurrences)
		ent = entities.FilterZAPAlertsOnly(ent)
		fmt.Printf("Filtered to ZAP scanner alerts: definitions %d->%d findings %d->%d occurrences %d->%d\n", beforeDefs, len(ent.Definitions), beforeFindings, len(ent.Findings), beforeOccurrences, len(ent.Occurrences))
	}
	if dropped := entities.DropMismatchedTraffic(&ent); dropped > 0 {
		fmt.Printf("Dropped mismatched traffic samples: %d\n", dropped)
	}
	entities.NormalizeAnalystStatuses(&ent)
	entities.EnsureCollections(&ent)
	if validation := entities.Validate(ent); !validation.OK() {
		return ent, scanLabel, fmt.Errorf("validate entities: %w", validation.Err())
	}
	if !opts.FetchAllowed {
		printEnrichmentSummary(ent, newDefs)
	}
	return ent, scanLabel, nil
}

func addRequestedDefinitions(ctx context.Context, ent *entities.EntitiesFile, opts entityPipelineOptions) int {
	if strings.TrimSpace(opts.Plugins) == "" && !opts.AllPlugins && !opts.InitMode {
		return 0
	}
	plugins := strings.TrimSpace(opts.Plugins)
	var fields []string
	if opts.AllPlugins || strings.EqualFold(plugins, "all") || (opts.InitMode && plugins == "") {
		fields = zapmeta.ListAllPluginIDs(ctx)
	} else {
		fields = strings.FieldsFunc(opts.Plugins, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	}
	index := make(map[string]struct{}, len(ent.Definitions))
	for _, definition := range ent.Definitions {
		index[strings.TrimSpace(definition.DefinitionID)] = struct{}{}
	}
	added := 0
	for _, pluginID := range fields {
		pluginID = strings.TrimSpace(pluginID)
		if pluginID == "" {
			continue
		}
		id := "def-" + pluginID
		if _, exists := index[id]; exists {
			continue
		}
		ent.Definitions = append(ent.Definitions, entities.Definition{DefinitionID: id, PluginID: pluginID})
		index[id] = struct{}{}
		added++
	}
	return added
}

func printEnrichmentSummary(ent entities.EntitiesFile, newDefinitions int) {
	detectionCount, sourceCount, titled := 0, 0, 0
	for _, definition := range ent.Definitions {
		if definition.Detection != nil {
			detectionCount++
			if strings.TrimSpace(definition.Detection.RuleSource) != "" || strings.TrimSpace(definition.Detection.SourceURL) != "" {
				sourceCount++
			}
		}
		if strings.TrimSpace(definition.Alert) != "" || strings.TrimSpace(definition.Name) != "" {
			titled++
		}
	}
	fmt.Printf("Init summary: defs total=%d new=%d detection=%d with-source=%d titled=%d\n", len(ent.Definitions), newDefinitions, detectionCount, sourceCount, titled)
}
