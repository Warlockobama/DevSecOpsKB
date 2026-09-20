package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
)

type pipelineInputOptions struct {
	RunIn      string
	EntitiesIn string
	AlertsIn   string
	ZapURL     string
	APIKey     string
	BaseURL    string
	Count      int
	InitMode   bool
	AllPlugins bool
	Plugins    string
	ScanLabel  string
	SiteLabel  string
	ZapBaseURL string
}

type pipelineInput struct {
	Client       *zapclient.Client
	Alerts       []zapclient.Alert
	Entities     entities.EntitiesFile
	FetchAllowed bool
	ScanLabel    string
	SiteLabel    string
	ZapBaseURL   string
	DiscoveryCtx context.Context
	Cancel       context.CancelFunc
}

// loadPipelineInput owns validated artifact ingestion and optional ZAP fetch.
// It has no output or publication side effects and derives all network work
// from the caller's cancellation context.
func loadPipelineInput(parent context.Context, opts pipelineInputOptions) (pipelineInput, error) {
	result := pipelineInput{
		ScanLabel:  opts.ScanLabel,
		SiteLabel:  opts.SiteLabel,
		ZapBaseURL: opts.ZapBaseURL,
	}
	if strings.TrimSpace(opts.RunIn) != "" {
		artifact, validation, err := runartifact.ReadValidated(opts.RunIn)
		if err != nil {
			return result, fmt.Errorf("read -run-in: %w", err)
		}
		reportInputNormalizations("-run-in", validation)
		result.Entities = artifact.Entities
		result.Alerts = append(result.Alerts, artifact.Alerts...)
		if strings.TrimSpace(result.ScanLabel) == "" && strings.TrimSpace(artifact.Meta.ScanLabel) != "" {
			result.ScanLabel = artifact.Meta.ScanLabel
		}
		if strings.TrimSpace(result.SiteLabel) == "" && strings.TrimSpace(artifact.Meta.SiteLabel) != "" {
			result.SiteLabel = artifact.Meta.SiteLabel
		}
		if strings.TrimSpace(result.ZapBaseURL) == "" && strings.TrimSpace(artifact.Meta.ZapBaseURL) != "" {
			result.ZapBaseURL = artifact.Meta.ZapBaseURL
		}
	}
	result.DiscoveryCtx, result.Cancel = context.WithTimeout(parent, 2*time.Minute)
	fail := func(err error) (pipelineInput, error) {
		result.Cancel()
		return result, err
	}

	result.FetchAllowed = strings.TrimSpace(opts.AlertsIn) == "" && strings.TrimSpace(opts.RunIn) == "" &&
		!opts.InitMode && strings.TrimSpace(opts.EntitiesIn) == "" && !opts.AllPlugins && strings.TrimSpace(opts.Plugins) == ""
	switch {
	case strings.TrimSpace(opts.AlertsIn) != "":
		f, err := os.Open(opts.AlertsIn)
		if err != nil {
			return fail(errors.New("open -in file: operation failed (private details omitted)"))
		}
		decodeErr := json.NewDecoder(f).Decode(&result.Alerts)
		_ = f.Close()
		if decodeErr != nil {
			return fail(errors.New("decode -in file: operation failed (private details omitted)"))
		}
	case result.FetchAllowed:
		client, err := zapclient.NewClient(opts.ZapURL, opts.APIKey)
		if err != nil {
			return fail(errors.New("new client: operation failed (private details omitted)"))
		}
		result.Client = client
		if opts.Count > 0 {
			result.Alerts, err = client.GetAlerts(result.DiscoveryCtx, zapclient.AlertsFilter{BaseURL: opts.BaseURL, Count: opts.Count, Start: 0, Recurse: true})
		} else {
			result.Alerts, err = client.GetAllAlerts(result.DiscoveryCtx, zapclient.AlertsFilter{BaseURL: opts.BaseURL, Recurse: true})
		}
		if err != nil {
			return fail(errors.New("get alerts: operation failed (private details omitted)"))
		}
	}

	if strings.TrimSpace(opts.EntitiesIn) != "" && strings.TrimSpace(opts.RunIn) == "" {
		var validation runartifact.ValidationResult
		var err error
		result.Entities, validation, err = runartifact.ReadEntities(opts.EntitiesIn)
		if err != nil {
			return fail(fmt.Errorf("read -entities-in: %w", err))
		}
		reportInputNormalizations("-entities-in", validation)
	}
	return result, nil
}
