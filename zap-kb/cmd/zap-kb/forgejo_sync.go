package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/forgejo"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

// defaultForgejoRedact is the redaction list applied to data published to
// Forgejo (issue bodies and wiki pages) unless overridden. It scrubs
// credential-bearing fields (Authorization, cookies, API-key headers) while
// leaving URLs and evidence intact so issues stay actionable. Forgejo is a
// shared export surface, so redaction is on by default; pass
// -forgejo-redact=off to disable.
const defaultForgejoRedact = "auth,cookies,headers"

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
	Redact       string // redaction list for published content; "off"/"none" disables

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

// forgejoRedactOptions resolves the -forgejo-redact flag value into redaction
// options. Returns (options, enabled).
func forgejoRedactOptions(list string) (entities.RedactOptions, bool) {
	v := strings.ToLower(strings.TrimSpace(list))
	if v == "off" || v == "none" {
		return entities.RedactOptions{}, false
	}
	if v == "" {
		v = defaultForgejoRedact
	}
	return entities.ParseRedactOptionList(v), true
}

// redactedCopy deep-copies an EntitiesFile via JSON round-trip and applies the
// given redactions to the copy. The original is never mutated — the unredacted
// entities remain the local system of record; only the published derivative is
// scrubbed.
func redactedCopy(ent entities.EntitiesFile, ro entities.RedactOptions) (entities.EntitiesFile, error) {
	raw, err := json.Marshal(ent)
	if err != nil {
		return entities.EntitiesFile{}, fmt.Errorf("marshal entities for redaction: %w", err)
	}
	var cp entities.EntitiesFile
	if err := json.Unmarshal(raw, &cp); err != nil {
		return entities.EntitiesFile{}, fmt.Errorf("unmarshal entities for redaction: %w", err)
	}
	entities.RedactEntities(&cp, ro)
	return cp, nil
}

// runForgejoPublish pushes findings to Forgejo as issues, pulls their state
// back, persists ticket refs into the entities file (so re-runs dedup without a
// remote scan), and — when opts.Wiki is set — publishes the vault to the repo
// wiki. It mutates *ent in place when status write-back is enabled.
//
// Published content (issue bodies, wiki pages) is rendered from a redacted
// copy of the entities by default; the KB-side entities file keeps the
// unredacted data.
//
// Returns the number of publish failures (issue create errors + wiki errors).
// Callers should turn a non-zero count into a non-zero process exit so CI and
// the CronJob report partial failure instead of silently succeeding.
func runForgejoPublish(ent *entities.EntitiesFile, opts forgejoPublishOptions) int {
	failures := 0

	// Build the publish view: redacted copy by default, raw when disabled.
	pubEnt := *ent
	ro, redactOn := forgejoRedactOptions(opts.Redact)
	if redactOn {
		cp, err := redactedCopy(*ent, ro)
		if err != nil {
			log.Fatalf("forgejo redaction: %v", err)
		}
		pubEnt = cp
	}

	exCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sum, err := forgejo.Export(exCtx, pubEnt, forgejo.Options{
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
	fmt.Printf("Forgejo: created=%d skipped=%d errors=%d duplicates_closed=%d\n", sum.Created, sum.Skipped, sum.Errors, sum.DuplicatesClosed)
	failures += sum.Errors

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

	// Optional wiki publish (Confluence analog). The wiki is always rendered
	// from the publish view (redacted by default): when redaction is on, a
	// dedicated vault snapshot is written to a temp dir so a pre-existing
	// unredacted local vault is never pushed to the shared wiki.
	if opts.Wiki && !opts.DryRun {
		wikiVault := strings.TrimSpace(opts.Vault)
		if wikiVault == "" {
			log.Printf("warning: -forgejo-wiki requires a vault path (-obsidian-dir); skipping wiki publish")
			failures++
			return failures
		}
		if redactOn {
			tmp, terr := os.MkdirTemp("", "forgejo-wiki-vault-")
			if terr != nil {
				log.Printf("warning: could not create redacted wiki vault dir: %v", terr)
				return failures + 1
			}
			defer os.RemoveAll(tmp)
			if err := writeVaultSnapshot(tmp, pubEnt, opts.ScanLabel, opts.SiteLabel, opts.ZapBaseURL, "", nil, nil, ""); err != nil {
				log.Printf("warning: could not write redacted vault for forgejo wiki: %v", err)
				return failures + 1
			}
			wikiVault = tmp
		} else if strings.TrimSpace(opts.Format) != "obsidian" {
			if err := writeVaultSnapshot(wikiVault, pubEnt, opts.ScanLabel, opts.SiteLabel, opts.ZapBaseURL, "", nil, nil, ""); err != nil {
				log.Printf("warning: could not write vault for forgejo wiki: %v", err)
				return failures + 1
			}
		}
		wikiCtx, wcancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer wcancel()
		wsum, werr := forgejo.ExportWiki(wikiCtx, wikiVault, forgejo.WikiOptions{
			BaseURL:     opts.BaseURL,
			Token:       opts.Token,
			Owner:       opts.Owner,
			Repo:        opts.Repo,
			Concurrency: opts.Concurrency,
		})
		if werr != nil {
			log.Printf("error: forgejo wiki export failed: %v", werr)
			failures++
		} else {
			fmt.Printf("Forgejo wiki: created=%d updated=%d skipped=%d errors=%d\n", wsum.Created, wsum.Updated, wsum.Skipped, wsum.Errors)
			failures += wsum.Errors
		}
	}
	return failures
}
