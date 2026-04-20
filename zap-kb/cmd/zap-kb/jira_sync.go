package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/confluence"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jsondump"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

type jiraSyncContext struct {
	Format           string
	Out              string
	EntitiesIn       string
	RunIn            string
	RunInputArtifact *runartifact.Artifact
}

type confluencePublishOptions struct {
	BaseURL          string
	Username         string
	APIToken         string
	SpaceKey         string
	ParentPageID     string
	TitlePrefix      string
	DryRun           bool
	Full             bool
	Concurrency      int
	ScanLabel        string
	SiteLabel        string
	ZapBaseURL       string
	JiraBaseURL      string
	JiraStatusByKey   map[string]string
	JiraAssigneeByKey map[string]string
	JiraStatusSynced  string
}

// mergeDefinitionEpicRefs persists Epic issue keys onto each Definition so
// subsequent runs reuse the same Epic rather than creating duplicates. Returns
// the count of definitions whose EpicRef was updated.
func mergeDefinitionEpicRefs(ent *entities.EntitiesFile, epicKeys map[string]string) int {
	if ent == nil || len(epicKeys) == 0 {
		return 0
	}
	updated := 0
	for i := range ent.Definitions {
		key := strings.TrimSpace(epicKeys[ent.Definitions[i].DefinitionID])
		if key == "" {
			continue
		}
		if strings.TrimSpace(ent.Definitions[i].EpicRef) == key {
			continue
		}
		ent.Definitions[i].EpicRef = key
		updated++
	}
	return updated
}

func mergeFindingTicketKeys(ent *entities.EntitiesFile, ticketKeys map[string]string) int {
	if ent == nil || len(ticketKeys) == 0 {
		return 0
	}
	added := 0
	for i := range ent.Findings {
		key := strings.TrimSpace(ticketKeys[ent.Findings[i].FindingID])
		if key == "" {
			continue
		}
		if ent.Findings[i].Analyst == nil {
			ent.Findings[i].Analyst = &entities.Analyst{}
		}
		if containsString(ent.Findings[i].Analyst.TicketRefs, key) {
			continue
		}
		ent.Findings[i].Analyst.TicketRefs = append(ent.Findings[i].Analyst.TicketRefs, key)
		added++
	}
	return added
}

func persistJiraEntities(ctx jiraSyncContext, ent entities.EntitiesFile) (string, error) {
	switch strings.TrimSpace(ctx.Format) {
	case "entities":
		return writeEntitiesFile(strings.TrimSpace(ctx.Out), ent)
	case "both":
		return writeEntitiesFile(strings.TrimSpace(ctx.Out)+".entities.json", ent)
	case "obsidian":
		if art := ctx.RunInputArtifact; art != nil && strings.TrimSpace(ctx.RunIn) != "" {
			updated := *art
			updated.Entities = ent
			if err := runartifact.Write(ctx.RunIn, updated); err != nil {
				return "", err
			}
			return ctx.RunIn, nil
		}
		if path := strings.TrimSpace(ctx.RunIn); path != "" {
			return writeEntitiesFile(path, ent)
		}
		if path := strings.TrimSpace(ctx.EntitiesIn); path != "" {
			return writeEntitiesFile(path, ent)
		}
		return "", fmt.Errorf("persistJiraEntities: obsidian format requires -run-in or -entities-in to persist finding ticket keys safely")
	}
	return "", nil
}

func writeEntitiesFile(path string, ent entities.EntitiesFile) (string, error) {
	if path == "" || path == "-" {
		return "", nil
	}
	if err := jsondump.WritePretty(path, ent); err != nil {
		return "", err
	}
	return path, nil
}

func shouldCarryForwardOccurrenceMeta(sourceTool string) bool {
	switch strings.ToLower(strings.TrimSpace(sourceTool)) {
	case "zap", "nuclei", "multi":
		return false
	default:
		return true
	}
}

func writeVaultSnapshot(root string, ent entities.EntitiesFile, scanLabel, siteLabel, zapBase, jiraBase string, jiraStatusByKey, jiraAssigneeByKey map[string]string, jiraStatusSynced string) error {
	return obsidian.WriteVault(root, ent, obsidian.Options{
		ScanLabel:                  scanLabel,
		SiteLabel:                  siteLabel,
		ZapBaseURL:                 zapBase,
		JiraBaseURL:                jiraBase,
		JiraStatusByKey:            jiraStatusByKey,
		JiraAssigneeByKey:          jiraAssigneeByKey,
		JiraStatusSynced:           jiraStatusSynced,
		TriageGuidanceFn:           zapmeta.TriageGuidance,
		CarryForwardOccurrenceMeta: shouldCarryForwardOccurrenceMeta(ent.SourceTool),
	})
}

func publishConfluenceVault(vault, format string, ent entities.EntitiesFile, opts confluencePublishOptions) (confluence.VaultSummary, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return confluence.VaultSummary{}, nil
	}
	if strings.TrimSpace(vault) == "" {
		return confluence.VaultSummary{}, fmt.Errorf("vault path is required for Confluence export")
	}
	if strings.TrimSpace(format) != "obsidian" {
		if err := writeVaultSnapshot(vault, ent, opts.ScanLabel, opts.SiteLabel, opts.ZapBaseURL, opts.JiraBaseURL, opts.JiraStatusByKey, opts.JiraAssigneeByKey, opts.JiraStatusSynced); err != nil {
			return confluence.VaultSummary{}, fmt.Errorf("write obsidian for confluence: %w", err)
		}
	}
	if opts.Full {
		confCtx, confCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer confCancel()
		sum, err := confluence.ExportVault(confCtx, vault, confluence.VaultOptions{
			BaseURL:          opts.BaseURL,
			Username:         opts.Username,
			APIToken:         opts.APIToken,
			SpaceKey:         opts.SpaceKey,
			DryRun:           opts.DryRun,
			Concurrency:      opts.Concurrency,
			JiraBaseURL:      opts.JiraBaseURL,
			JiraStatusByKey:   opts.JiraStatusByKey,
			JiraAssigneeByKey: opts.JiraAssigneeByKey,
			JiraStatusSynced:  opts.JiraStatusSynced,
			Entities:         &ent,
		})
		if err != nil {
			return confluence.VaultSummary{}, fmt.Errorf("confluence vault export: %w", err)
		}
		fmt.Printf("Confluence: created=%d updated=%d skipped=%d errors=%d\n", sum.Created, sum.Updated, sum.Skipped, sum.Errors)
		return sum, nil
	}
	confCtx, confCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer confCancel()
	if err := confluence.Export(confCtx, vault, confluence.Options{
		BaseURL:      opts.BaseURL,
		Username:     opts.Username,
		APIToken:     opts.APIToken,
		SpaceKey:     opts.SpaceKey,
		ParentPageID: opts.ParentPageID,
		TitlePrefix:  opts.TitlePrefix,
		MarkdownPage: "INDEX.md",
		DryRun:       opts.DryRun,
	}); err != nil {
		return confluence.VaultSummary{}, fmt.Errorf("confluence export: %w", err)
	}
	fmt.Println("Exported INDEX.md to Confluence")
	return confluence.VaultSummary{}, nil
}

func containsString(items []string, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, item := range items {
		if strings.TrimSpace(item) == want {
			return true
		}
	}
	return false
}

func hasFindingTicketRefs(ent entities.EntitiesFile) bool {
	for _, finding := range ent.Findings {
		if finding.Analyst == nil {
			continue
		}
		for _, ref := range finding.Analyst.TicketRefs {
			if strings.TrimSpace(ref) != "" {
				return true
			}
		}
	}
	return false
}

func validatePublishSource(ent entities.EntitiesFile, wantConfluence, wantJira, allowAgentPublish, allowCustomPublish bool) error {
	if !wantConfluence && !wantJira {
		return nil
	}
	source := strings.ToLower(strings.TrimSpace(ent.SourceTool))
	var targets []string
	if wantConfluence {
		targets = append(targets, "Confluence")
	}
	if wantJira {
		targets = append(targets, "Jira")
	}
	if source != "" && strings.Contains(source, "agent") && !allowAgentPublish {
		return fmt.Errorf("refusing to publish %s data from sourceTool=%q; use scanner-native inputs like zap-report/nuclei-report or pass -allow-agent-publish to override", strings.Join(targets, "+"), ent.SourceTool)
	}
	if containsCustomDefinitions(ent) && !allowCustomPublish {
		return fmt.Errorf("refusing to publish %s data containing custom definitions; use scanner-native inputs only or pass -allow-custom-publish to override", strings.Join(targets, "+"))
	}
	return nil
}

func containsCustomDefinitions(ent entities.EntitiesFile) bool {
	for i := range ent.Definitions {
		if entities.IsCustomDefinition(&ent.Definitions[i]) {
			return true
		}
	}
	return false
}
