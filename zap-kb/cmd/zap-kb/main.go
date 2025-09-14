package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"zap-kb/internal/entities"
	"zap-kb/internal/output/jsondump"
	"zap-kb/internal/output/obsidian"
	"zap-kb/internal/zapclient"
	"zap-kb/internal/zapmeta"
)

func main() {
	var (
		zapURL         string
		apiKey         string
		baseURL        string
		count          int
		out            string
		merge          bool
		format         string
		source         string
		vault          string
		infile         string
		entitiesIn     string
		plugins        string
		allPlugins     bool
		genAt          string
		includeTraffic bool
		trafficMax     int
		scanLabel      string
		siteLabel      string
		trafficScope   string
		zapBase        string
		includeDetect  bool
		detectDetails  string
		initMode       bool
	)
	flag.StringVar(&zapURL, "zap-url", "http://127.0.0.1:8090", "ZAP API base URL")
	flag.StringVar(&apiKey, "api-key", "", "ZAP API key (if required)")
	flag.StringVar(&baseURL, "baseurl", "", "Filter alerts by baseurl (optional)")
	flag.IntVar(&count, "count", 0, "Number of alerts to fetch (0 = all)")
	flag.StringVar(&out, "out", "docs/data/alerts.json", "Write JSON to this path")
	flag.BoolVar(&merge, "merge", false, "Merge with existing JSON (de-duplicate)")
	flag.StringVar(&format, "format", "entities", "Output format: entities|flat|both|obsidian")
	flag.StringVar(&source, "source", "zap", "Source tool name (zap, burp, etc.)")
	flag.StringVar(&vault, "obsidian-dir", "docs/obsidian", "Output dir for Obsidian vault (when -format=obsidian)")
	flag.StringVar(&infile, "in", "", "Optional input file of ZAP alerts (JSON array); skips API fetch when set")
	flag.StringVar(&entitiesIn, "entities-in", "", "Optional input Entities JSON to merge/enrich; enables enrich-only mode when no alerts")
	flag.StringVar(&plugins, "plugins", "", "Comma/space-separated list of plugin IDs to add/update definitions for (enrich-only capable). Use 'all' to update all known plugins.")
	flag.BoolVar(&allPlugins, "all-plugins", false, "Discover all ZAP plugins from docs and update their definitions (enrich-only capable)")
	flag.StringVar(&genAt, "generated-at", "", "Optional RFC3339 timestamp to set in entities output for stable diffs")
	flag.BoolVar(&includeTraffic, "include-traffic", false, "Enrich with first-occurrence HTTP request/response snippets")
	flag.IntVar(&trafficMax, "traffic-max-bytes", 2048, "Max bytes to capture for request/response snippets")
	flag.StringVar(&trafficScope, "traffic-scope", "first", "Traffic enrichment scope: first|all")
	flag.StringVar(&scanLabel, "scan-label", "", "Optional label for this scan/session (appears in INDEX and frontmatter)")
	flag.StringVar(&siteLabel, "site-label", "", "Optional site/domain label override when domains are redacted")
	flag.StringVar(&zapBase, "zap-base-url", "", "Optional ZAP base URL to link back to messages in Obsidian")
	flag.BoolVar(&includeDetect, "include-detection", false, "Enrich with detection logic links from ZAP docs/GitHub")
	flag.StringVar(&detectDetails, "detection-details", "links", "Detection enrichment detail: links|summary")
	flag.BoolVar(&initMode, "init", false, "Init KB without run data: seed/update definitions only (no alert fetch)")
	flag.Parse()

	var (
		client *zapclient.Client
		alerts []zapclient.Alert
		entIn  entities.EntitiesFile
		err    error
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Decide if we should fetch alerts from ZAP API
	// Fetch only when not explicitly in init/enrich-only modes and no explicit entities/plugin list is provided.
	fetchAllowed := strings.TrimSpace(infile) == "" && !initMode && strings.TrimSpace(entitiesIn) == "" && !allPlugins && strings.TrimSpace(plugins) == ""

	if strings.TrimSpace(infile) != "" {
		// Read alerts from file and skip API calls
		f, err := os.Open(infile)
		if err != nil {
			log.Fatalf("open -in file: %v", err)
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		if err := dec.Decode(&alerts); err != nil {
			log.Fatalf("decode -in file: %v", err)
		}
	} else if fetchAllowed { // fetch only when not enrich-only
		// Fetch from ZAP API
		client, err = zapclient.NewClient(zapURL, apiKey)
		if err != nil {
			log.Fatalf("new client: %v", err)
		}
		// Default = all alerts; -count N restricts to first N
		if count > 0 {
			alerts, err = client.GetAlerts(ctx, zapclient.AlertsFilter{
				BaseURL: baseURL, Count: count, Start: 0, Recurse: true,
			})
		} else {
			alerts, err = client.GetAllAlerts(ctx, zapclient.AlertsFilter{
				BaseURL: baseURL, Recurse: true,
			})
		}
		if err != nil {
			log.Fatalf("get alerts: %v", err)
		}
	} else {
		// Helpful note for offline init/enrich-only runs
		if initMode || allPlugins || strings.TrimSpace(plugins) != "" || strings.TrimSpace(entitiesIn) != "" {
			fmt.Println("Init/enrich-only mode: skipping ZAP API fetch")
		}
	}

	// Optional input Entities for merge/enrich-only
	if strings.TrimSpace(entitiesIn) != "" {
		f, err := os.Open(entitiesIn)
		if err != nil {
			log.Fatalf("open -entities-in file: %v", err)
		}
		defer f.Close()
		if err := json.NewDecoder(f).Decode(&entIn); err != nil {
			log.Fatalf("decode -entities-in file: %v", err)
		}
	}

	// optional merge (flat alerts only)
	if merge {
		if format == "flat" || format == "both" {
			var existing []zapclient.Alert
			_ = jsondump.ReadIfExists(out, &existing)
			alerts = append(existing, alerts...)
		} else {
			fmt.Println("Note: -merge is for flat alerts; use -entities-in to merge entities")
		}
	}

	// always dedup before write
	alerts = zapclient.DeduplicateAlerts(alerts)

	// preview
	fmt.Printf("Fetched %d alerts (after dedup)\n", len(alerts))
	for i, a := range alerts {
		if i >= 5 {
			break
		}
		fmt.Printf("[%d] %s | risk=%s url=%s param=%s plugin=%s cwe=%d\n",
			i, a.Alert, a.Risk, a.URL, a.Param, a.PluginID, a.CWEID.Int())
	}

	// Build entities model (or merge/enrich) if needed by chosen output
	var ent entities.EntitiesFile
	if format == "entities" || format == "both" || format == "obsidian" {
		if len(entIn.Definitions) > 0 || len(entIn.Findings) > 0 || len(entIn.Occurrences) > 0 {
			ent = entIn
		}
		if len(alerts) > 0 {
			built := entities.BuildEntities(alerts, source)
			if len(ent.Definitions) == 0 && len(ent.Findings) == 0 && len(ent.Occurrences) == 0 {
				ent = built
			} else {
				ent = entities.Merge(ent, built)
			}
		}

		// Ensure definitions exist for explicit/all plugin IDs (or default-all when init mode)
		var newDefs int
		if strings.TrimSpace(plugins) != "" || allPlugins || initMode {
			// Accept comma or space separators
			var fields []string
			ptrim := strings.TrimSpace(plugins)
			if allPlugins || strings.EqualFold(ptrim, "all") || (initMode && ptrim == "") {
				fields = zapmeta.ListAllPluginIDs(ctx)
			} else {
				fields = strings.FieldsFunc(plugins, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
			}
			if len(fields) > 0 {
				// Build an index for existing defs
				defIndex := map[string]struct{}{}
				for _, d := range ent.Definitions {
					defIndex[strings.TrimSpace(d.DefinitionID)] = struct{}{}
				}
				for _, pid := range fields {
					pid = strings.TrimSpace(pid)
					if pid == "" {
						continue
					}
					id := "def-" + pid
					if _, ok := defIndex[id]; ok {
						continue
					}
					// Add a stub definition; enrichment will fill detection/title.
					ent.Definitions = append(ent.Definitions, entities.Definition{
						DefinitionID: id,
						PluginID:     pid,
					})
					defIndex[id] = struct{}{}
					newDefs++
				}
			}
		}
		// optional override of generatedAt for stable diffs during iteration
		if strings.TrimSpace(genAt) != "" {
			ent.GeneratedAt = genAt
		}
		// fill defaults if missing (e.g., plugins-only mode)
		if strings.TrimSpace(ent.SchemaVersion) == "" {
			ent.SchemaVersion = "v1"
		}
		if strings.TrimSpace(ent.SourceTool) == "" {
			ent.SourceTool = source
		}
		if strings.TrimSpace(ent.GeneratedAt) == "" {
			ent.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if includeTraffic {
			if trafficScope == "all" {
				_ = entities.EnrichAllTraffic(ctx, client, &ent, trafficMax)
			} else {
				_ = entities.EnrichFirstTraffic(ctx, client, &ent, trafficMax)
			}
		}
		if includeDetect {
			entities.EnrichDetections(ctx, &ent)
			if strings.ToLower(strings.TrimSpace(detectDetails)) == "summary" {
				entities.EnrichDetectionSummaries(ctx, &ent)
			}
		}

		// Print a concise init/enrich summary when not fetching alerts
		if fetchAllowed == false { // enrich-only / init flows
			// detection stats
			defsTotal := len(ent.Definitions)
			detCount, srcCount, titled := 0, 0, 0
			for _, d := range ent.Definitions {
				if d.Detection != nil {
					detCount++
					if strings.TrimSpace(d.Detection.RuleSource) != "" || strings.TrimSpace(d.Detection.SourceURL) != "" {
						srcCount++
					}
				}
				if strings.TrimSpace(d.Alert) != "" || strings.TrimSpace(d.Name) != "" {
					titled++
				}
			}
			fmt.Printf("Init summary: defs total=%d new=%d detection=%d with-source=%d titled=%d\n", defsTotal, newDefs, detCount, srcCount, titled)
		}
	}

	// write
	switch format {
	case "entities":
		if err := jsondump.WritePretty(out, ent); err != nil {
			log.Fatalf("write json: %v", err)
		}
	case "flat":
		if err := jsondump.WritePretty(out, alerts); err != nil {
			log.Fatalf("write json: %v", err)
		}
	case "both":
		if err := jsondump.WritePretty(out, alerts); err != nil {
			log.Fatalf("write json flat: %v", err)
		}
		if err := jsondump.WritePretty(out+".entities.json", ent); err != nil {
			log.Fatalf("write json entities: %v", err)
		}
	case "obsidian":
		if err := obsidian.WriteVault(vault, ent, obsidian.Options{ScanLabel: scanLabel, SiteLabel: siteLabel, ZapBaseURL: zapBase}); err != nil {
			log.Fatalf("write obsidian: %v", err)
		}
	default:
		log.Fatalf("unknown -format %q (use entities|flat|both|obsidian)", format)
	}

	// Exit code 2 only when no content produced at all (no alerts and no entities).
	if (format == "flat" || format == "both") && len(alerts) == 0 && len(ent.Definitions) == 0 {
		os.Exit(2)
	}
}
