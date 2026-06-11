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

	// Link issues to the KB wiki definition page only when the wiki is being
	// published this run, so issues never point at a wiki that does not exist.
	wikiURLBase := ""
	if opts.Wiki {
		wikiURLBase = fmt.Sprintf("%s/%s/%s/wiki", strings.TrimRight(opts.BaseURL, "/"), opts.Owner, opts.Repo)
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
		WikiURLBase: wikiURLBase,
	})
	if err != nil {
		log.Fatalf("forgejo export: %v", err)
	}
	fmt.Printf("Forgejo: created=%d reopened=%d updated=%d skipped=%d errors=%d duplicates_closed=%d\n",
		sum.Created, sum.Reopened, sum.BodiesUpdated, sum.Skipped, sum.Errors, sum.DuplicatesClosed)
	failures += sum.Errors

	addedTicketKeys := 0
	if !opts.DryRun && len(sum.TicketRefs) > 0 {
		addedTicketKeys = mergeForgejoTicketRefs(ent, sum.TicketRefs, opts.Owner+"/"+opts.Repo)
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

// mergeForgejoTicketRefs records this run's findingID→issueRef map on the
// findings. Unlike the generic append-only Jira merge, any existing ref that
// parses as an issue of the SAME Forgejo repo but differs from the new ref is
// removed first: the new ref is always the reconcile winner, and a stale ref
// left pointing at a closed duplicate would make the next status pull mark the
// finding "fixed" while the winning issue is still open. Refs belonging to
// other trackers (Jira keys, other repos) are preserved untouched. Returns the
// number of findings whose refs changed.
func mergeForgejoTicketRefs(ent *entities.EntitiesFile, ticketRefs map[string]string, repoPrefix string) int {
	if ent == nil || len(ticketRefs) == 0 {
		return 0
	}
	changed := 0
	for i := range ent.Findings {
		ref := strings.TrimSpace(ticketRefs[ent.Findings[i].FindingID])
		if ref == "" {
			continue
		}
		if ent.Findings[i].Analyst == nil {
			ent.Findings[i].Analyst = &entities.Analyst{}
		}
		old := ent.Findings[i].Analyst.TicketRefs
		kept := make([]string, 0, len(old)+1)
		present := false
		mutated := false
		for _, existing := range old {
			if existing == ref {
				kept = append(kept, existing)
				present = true
				continue
			}
			if _, ok := forgejo.ExtractIssueNumber(existing, repoPrefix); ok {
				// Some other ref into this repo — a stale duplicate (different
				// number) or a different spelling of the same issue; the
				// canonical new ref replaces it either way.
				mutated = true
				continue
			}
			kept = append(kept, existing) // foreign tracker ref — preserve
		}
		if !present {
			kept = append(kept, ref)
			mutated = true
		}
		ent.Findings[i].Analyst.TicketRefs = kept
		if mutated {
			changed++
		}
	}
	return changed
}
