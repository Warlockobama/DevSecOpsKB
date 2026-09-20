package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/confluence"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jsondump"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

type jiraSyncContext struct {
	Format string
	Out    string
}

type confluencePublishOptions struct {
	Context           context.Context
	Redact            entities.RedactOptions
	BaseURL           string
	Username          string
	APIToken          string
	SpaceKey          string
	ParentPageID      string
	TitlePrefix       string
	DryRun            bool
	Full              bool
	Concurrency       int
	ScanLabel         string
	SiteLabel         string
	ZapBaseURL        string
	JiraBaseURL       string
	JiraStatusByKey   map[string]string
	JiraAssigneeByKey map[string]string
	JiraStatusSynced  string
	JiraServerID      string
	JiraServerName    string
	JiraProjectKey    string
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

func collectFindingTicketRefs(ent entities.EntitiesFile) map[string][]string {
	out := make(map[string][]string)
	for _, finding := range ent.Findings {
		findingID := strings.TrimSpace(finding.FindingID)
		if findingID == "" || finding.Analyst == nil {
			continue
		}
		for _, ref := range finding.Analyst.TicketRefs {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			if !containsString(out[findingID], ref) {
				out[findingID] = append(out[findingID], ref)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func shouldPersistJiraEntities(addedTicketKeys, updatedEpicRefs int, jiraSyncKBStatus bool, ent entities.EntitiesFile) bool {
	return addedTicketKeys > 0 || updatedEpicRefs > 0 || (jiraSyncKBStatus && hasFindingTicketRefs(ent))
}

func persistJiraEntities(ctx jiraSyncContext, ent entities.EntitiesFile) (string, error) {
	switch strings.TrimSpace(ctx.Format) {
	case "entities":
		return writeEntitiesFile(strings.TrimSpace(ctx.Out), ent)
	case "both":
		return writeEntitiesFile(strings.TrimSpace(ctx.Out)+".entities.json", ent)
	case "obsidian":
		// The vault and optional -run-out are derived outputs. Producer-owned
		// -run-in and -entities-in artifacts are immutable; publication refs are
		// persisted by publicationstate.Store instead.
		return "", nil
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

// writeVaultSnapshot writes the Obsidian vault with the pipeline's standard
// triage guidance and carry-forward policy applied on top of the caller's
// sink-specific options (Jira fields, tracker name, ticket linkifier, …).
func writeVaultSnapshot(root string, ent entities.EntitiesFile, opts obsidian.Options) error {
	opts.TriageGuidanceFn = zapmeta.TriageGuidance
	opts.CarryForwardOccurrenceMeta = shouldCarryForwardOccurrenceMeta(ent.SourceTool)
	opts.CarryForwardFindingMeta = shouldCarryForwardOccurrenceMeta(ent.SourceTool)
	return obsidian.WriteVault(root, ent, opts)
}

func publishConfluenceVault(vault, format string, ent entities.EntitiesFile, opts confluencePublishOptions) (confluence.VaultSummary, error) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(opts.BaseURL) == "" {
		return confluence.VaultSummary{}, nil
	}
	if strings.TrimSpace(vault) == "" {
		return confluence.VaultSummary{}, fmt.Errorf("vault path is required for Confluence export")
	}
	sourceVault := vault
	tmp, tmpErr := os.MkdirTemp("", "confluence-output-")
	if tmpErr != nil {
		return confluence.VaultSummary{}, fmt.Errorf("cannot create Confluence snapshot")
	}
	defer os.RemoveAll(tmp)
	vault = tmp
	{
		if err := writeVaultSnapshot(vault, ent, obsidian.Options{
			Redact:            opts.Redact,
			CarryForwardRoot:  sourceVault,
			ScanLabel:         opts.ScanLabel,
			SiteLabel:         opts.SiteLabel,
			ZapBaseURL:        opts.ZapBaseURL,
			JiraBaseURL:       opts.JiraBaseURL,
			JiraStatusByKey:   opts.JiraStatusByKey,
			JiraAssigneeByKey: opts.JiraAssigneeByKey,
			JiraStatusSynced:  opts.JiraStatusSynced,
		}); err != nil {
			return confluence.VaultSummary{}, fmt.Errorf("write obsidian for confluence: %w", err)
		}
	}
	if opts.Full {
		confCtx, confCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer confCancel()
		sum, err := confluence.ExportVault(confCtx, vault, confluence.VaultOptions{
			Redact:            opts.Redact,
			BaseURL:           opts.BaseURL,
			Username:          opts.Username,
			APIToken:          opts.APIToken,
			SpaceKey:          opts.SpaceKey,
			DryRun:            opts.DryRun,
			Concurrency:       opts.Concurrency,
			JiraBaseURL:       opts.JiraBaseURL,
			JiraStatusByKey:   opts.JiraStatusByKey,
			JiraAssigneeByKey: opts.JiraAssigneeByKey,
			JiraStatusSynced:  opts.JiraStatusSynced,
			JiraServerID:      opts.JiraServerID,
			JiraServerName:    opts.JiraServerName,
			JiraProjectKey:    opts.JiraProjectKey,
			Entities:          &ent,
		})
		if err != nil {
			return sum, fmt.Errorf("confluence vault export: %w", err)
		}
		fmt.Printf("Confluence: created=%d updated=%d skipped=%d errors=%d\n", sum.Created, sum.Updated, sum.Skipped, sum.Errors)
		return sum, nil
	}
	confCtx, confCancel := context.WithTimeout(ctx, 60*time.Second)
	defer confCancel()
	if err := confluence.Export(confCtx, vault, confluence.Options{
		Redact:       opts.Redact,
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

// parseJiraUserMap parses a comma-separated "owner=accountId" list into a
// map suitable for jira.Options.UsernameMap. Entries missing the "=" or with
// blank halves are skipped silently. Returns nil for empty input so callers
// can pass it through without checking.
func parseJiraUserMap(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 1 || eq == len(pair)-1 {
			continue
		}
		key := strings.TrimSpace(pair[:eq])
		val := strings.TrimSpace(pair[eq+1:])
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
