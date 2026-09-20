package main

import (
	"fmt"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jsondump"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/obsidian"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
)

type primaryOutputOptions struct {
	Format      string
	Out         string
	Vault       string
	ScanLabel   string
	SiteLabel   string
	ZapBaseURL  string
	JiraBaseURL string
	Redact      entities.RedactOptions
}

// writePrimaryOutput is the single owner of the initial local representation.
// Later sink state refreshes may update only explicit derived outputs.
func writePrimaryOutput(ent entities.EntitiesFile, alerts []zapclient.Alert, opts primaryOutputOptions) error {
	switch opts.Format {
	case "entities":
		return jsondump.WritePretty(opts.Out, ent)
	case "flat":
		return jsondump.WritePretty(opts.Out, alerts)
	case "both":
		if err := jsondump.WritePretty(opts.Out, alerts); err != nil {
			return err
		}
		return jsondump.WritePretty(opts.Out+".entities.json", ent)
	case "obsidian":
		return writeVaultSnapshot(opts.Vault, ent, obsidian.Options{ScanLabel: opts.ScanLabel, SiteLabel: opts.SiteLabel, ZapBaseURL: opts.ZapBaseURL, JiraBaseURL: opts.JiraBaseURL, Redact: opts.Redact})
	default:
		return fmt.Errorf("unknown output format")
	}
}
