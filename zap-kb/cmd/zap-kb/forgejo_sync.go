package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/forgejo"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

// forgejoPublishOptions bundles everything runForgejoPublish needs: the Forgejo
// connection + filtering knobs plus the vault/persistence context shared with
// the rest of the pipeline.
type forgejoPublishOptions struct {
	BaseURL      string
	Token        string
	Owner        string
	Repo         string
	MinRisk      string
	OptInTag     string
	ExtraLabels  []string
	Concurrency  int
	DryRun       bool
	SyncKBStatus bool
	Wiki         bool

	// Vault / persistence context.
	Format        string
	Vault         string
	Out           string
	EntitiesIn    string
	RunIn         string
	RunInArtifact *runartifact.Artifact
	ScanLabel     string
	SiteLabel     string
	ZapBaseURL    string
}

// runForgejoPublish pushes findings to Forgejo as issues, pulls their state
// back, persists ticket refs into the entities file (so re-runs dedup without a
// remote scan), and — when opts.Wiki is set — publishes the vault to the repo
// wiki. It mutates *ent in place when status write-back is enabled.
func runForgejoPublish(ent *entities.EntitiesFile, opts forgejoPublishOptions) {
	exCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := forgejo.Export(exCtx, *ent, forgejo.Options{
		BaseURL:     opts.BaseURL,
		Token:       opts.Token,
		Owner:       opts.Owner,
		Repo:        opts.Repo,
		ExtraLabels: opts.ExtraLabels,
		MinRisk:     opts.MinRisk,
		OptInTag:    opts.OptInTag,
		DryRun:      opts.DryRun,
		Concurrency: opts.Concurrency,
	})
	if err != nil {
		log.Fatalf("forgejo export: %v", err)
	}
	fmt.Printf("Forgejo: created=%d skipped=%d errors=%d\n", sum.Created, sum.Skipped, sum.Errors)

	addedTicketKeys := 0
	if !opts.DryRun && len(sum.TicketRefs) > 0 {
		addedTicketKeys = mergeFindingTicketKeys(ent, sum.TicketRefs)
	}

	// Pull issue state back. By default this is read-only (Forgejo is the
	// workflow source of truth); -forgejo-sync-kb-status mutates KB status.
	if !opts.DryRun && hasFindingTicketRefs(*ent) {
		pullCtx, pcancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer pcancel()
		pres, perr := forgejo.PullStatus(pullCtx, *ent, forgejo.PullOptions{
			BaseURL:  opts.BaseURL,
			Token:    opts.Token,
			Owner:    opts.Owner,
			Repo:     opts.Repo,
			ReadOnly: !opts.SyncKBStatus,
		})
		if perr != nil {
			log.Printf("warning: forgejo status pull failed: %v", perr)
		} else if opts.SyncKBStatus {
			*ent = pres.Updated
			fmt.Printf("Forgejo pull: updated=%d unchanged=%d notfound=%d unmapped=%d errors=%d\n",
				pres.Result.Updated, pres.Result.Unchanged, pres.Result.NotFound, pres.Result.Unmapped, pres.Result.Errors)
		} else {
			fmt.Printf("Forgejo pull: fetched=%d notfound=%d errors=%d (KB status write-back disabled)\n",
				pres.Result.Unchanged+pres.Result.Unmapped, pres.Result.NotFound, pres.Result.Errors)
		}
	}

	// Persist ticket refs / status back to the entities file so the next run
	// short-circuits dedup. Reuses the shared persistence helper.
	if !opts.DryRun && (addedTicketKeys > 0 || (opts.SyncKBStatus && hasFindingTicketRefs(*ent))) {
		savePath, werr := persistJiraEntities(jiraSyncContext{
			Format:           opts.Format,
			Out:              opts.Out,
			EntitiesIn:       opts.EntitiesIn,
			RunIn:            opts.RunIn,
			RunInputArtifact: opts.RunInArtifact,
		}, *ent)
		if werr != nil {
			log.Printf("warning: could not save Forgejo state to entities file: %v", werr)
		} else if savePath != "" {
			fmt.Printf("Forgejo: wrote current ticket/state data to %s\n", savePath)
		}
	}

	// Optional wiki publish (Confluence analog). Requires a vault; when the run
	// isn't already producing one, write a snapshot first.
	if opts.Wiki && !opts.DryRun {
		if strings.TrimSpace(opts.Vault) == "" {
			log.Printf("warning: -forgejo-wiki requires a vault path (-obsidian-dir); skipping wiki publish")
			return
		}
		if strings.TrimSpace(opts.Format) != "obsidian" {
			if err := writeVaultSnapshot(opts.Vault, *ent, opts.ScanLabel, opts.SiteLabel, opts.ZapBaseURL, "", nil, nil, ""); err != nil {
				log.Printf("warning: could not write vault for forgejo wiki: %v", err)
				return
			}
		}
		wikiCtx, wcancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer wcancel()
		wsum, werr := forgejo.ExportWiki(wikiCtx, opts.Vault, forgejo.WikiOptions{
			BaseURL:     opts.BaseURL,
			Token:       opts.Token,
			Owner:       opts.Owner,
			Repo:        opts.Repo,
			Concurrency: opts.Concurrency,
		})
		if werr != nil {
			log.Printf("warning: forgejo wiki export failed: %v", werr)
		} else {
			fmt.Printf("Forgejo wiki: created=%d updated=%d skipped=%d errors=%d\n", wsum.Created, wsum.Updated, wsum.Skipped, wsum.Errors)
		}
	}
}
