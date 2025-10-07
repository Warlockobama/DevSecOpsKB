package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type wizardInputs struct {
	ZapURL          *string
	APIKey          *string
	BaseURL         *string
	Count           *int
	Out             *string
	Vault           *string
	Format          *string
	SourceTool      *string
	InFile          *string
	EntitiesIn      *string
	RunIn           *string
	RunOut          *string
	ZipOut          *string
	IncludeTraffic  *bool
	TrafficScope    *string
	TrafficMaxBytes *int
	TrafficMaxPer   *int
	TrafficTotalMax *int
	TrafficMinRisk  *string
	IncludeDetect   *bool
	DetectDetails   *string
	ScanLabel       *string
	SiteLabel       *string
	ZapBaseURL      *string
}

func shouldLaunchWizard(enabled bool) bool {
	if !enabled || !isInteractiveTerminal() {
		return false
	}
	explicit := 0
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name != "wizard" {
			explicit++
		}
	})
	return explicit == 0
}

func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return false
	}
	if strings.EqualFold(os.Getenv("CI"), "true") {
		return false
	}
	return true
}

func runWizard(cfg wizardInputs) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("+------------------------------------------------+")
	fmt.Println("|           zap-kb Quickstart Wizard            |")
	fmt.Println("+------------------------------------------------+")
	fmt.Println("This wizard keeps the common cases simple. Disable with -wizard=false.")
	fmt.Println()

	// Data source selection
	sourceChoice := chooseOption(reader, "Where are your alerts coming from?", []string{
		"Live ZAP API",
		"Alerts JSON file",
		"Existing run artifact / entities JSON",
	}, 1)

	if cfg.InFile != nil {
		*cfg.InFile = ""
	}
	if cfg.RunIn != nil {
		*cfg.RunIn = ""
	}
	if cfg.EntitiesIn != nil {
		*cfg.EntitiesIn = ""
	}

	switch sourceChoice {
	case 1:
		fmt.Println("\n-- Live ZAP API --")
		if cfg.ZapURL != nil {
			*cfg.ZapURL = promptString(reader, "ZAP API URL", *cfg.ZapURL)
		}
		if cfg.APIKey != nil {
			*cfg.APIKey = promptString(reader, "ZAP API key (blank if none)", *cfg.APIKey)
		}
		if cfg.BaseURL != nil {
			*cfg.BaseURL = promptString(reader, "Filter by target base URL (blank for all)", *cfg.BaseURL)
		}
		if cfg.Count != nil {
			*cfg.Count = promptInt(reader, "Limit number of alerts (0 = all)", *cfg.Count)
		}
	case 2:
		fmt.Println("\n-- Alerts JSON file --")
		path := promptString(reader, "Path to alerts JSON", valueOr(cfg.InFile, "alerts.json"))
		if cfg.InFile != nil {
			*cfg.InFile = strings.TrimSpace(path)
		}
	case 3:
		fmt.Println("\n-- Run artifact / entities --")
		path := promptString(reader, "Path to run artifact or entities JSON", valueOr(cfg.RunIn, "docs/data/entities.json"))
		if cfg.RunIn != nil {
			*cfg.RunIn = strings.TrimSpace(path)
		}
	}

	if cfg.SourceTool != nil {
		*cfg.SourceTool = promptString(reader, "Source tool label", *cfg.SourceTool)
	}

	// Output format
	formats := []string{
		"Entities JSON",
		"Flat alerts JSON",
		"Both (alerts + entities)",
		"Obsidian vault",
	}
	currentFormat := valueOr(cfg.Format, "entities")
	defaultFmt := 1
	switch strings.ToLower(strings.TrimSpace(currentFormat)) {
	case "entities":
		defaultFmt = 1
	case "flat":
		defaultFmt = 2
	case "both":
		defaultFmt = 3
	case "obsidian":
		defaultFmt = 4
	}
	fmtChoice := chooseOption(reader, "Pick an output format", formats, defaultFmt)
	switch fmtChoice {
	case 1:
		setString(cfg.Format, "entities")
	case 2:
		setString(cfg.Format, "flat")
	case 3:
		setString(cfg.Format, "both")
	case 4:
		setString(cfg.Format, "obsidian")
	}

	if cfg.Out != nil {
		*cfg.Out = promptString(reader, "Output JSON path", *cfg.Out)
	}
	if cfg.Format != nil && strings.EqualFold(*cfg.Format, "obsidian") && cfg.Vault != nil {
		*cfg.Vault = promptString(reader, "Obsidian vault directory", *cfg.Vault)
	}

	// Detection enrichment
	if cfg.IncludeDetect != nil {
		includeDet := promptYesNo(reader, "Enrich with detection links?", *cfg.IncludeDetect)
		*cfg.IncludeDetect = includeDet
		if includeDet && cfg.DetectDetails != nil {
			detChoice := chooseOption(reader, "Detection detail level", []string{"Links only", "Links + summary"}, func() int {
				if strings.EqualFold(strings.TrimSpace(*cfg.DetectDetails), "summary") {
					return 2
				}
				return 1
			}())
			if detChoice == 2 {
				*cfg.DetectDetails = "summary"
			} else {
				*cfg.DetectDetails = "links"
			}
		}
	}

	// Traffic enrichment
	if cfg.IncludeTraffic != nil {
		includeTraffic := promptYesNo(reader, "Capture HTTP request/response snippets?", *cfg.IncludeTraffic)
		*cfg.IncludeTraffic = includeTraffic
		if includeTraffic {
			scopeChoice := chooseOption(reader, "Traffic scope", []string{"First observation per issue", "All observations"}, func() int {
				if strings.EqualFold(strings.TrimSpace(valueOr(cfg.TrafficScope, "first")), "all") {
					return 2
				}
				return 1
			}())
			if scopeChoice == 2 {
				setString(cfg.TrafficScope, "all")
			} else {
				setString(cfg.TrafficScope, "first")
				if cfg.TrafficMaxPer != nil {
					*cfg.TrafficMaxPer = promptInt(reader, "Max observations per issue", *cfg.TrafficMaxPer)
				}
			}
			if cfg.TrafficMinRisk != nil {
				riskChoice := chooseOption(reader, "Minimum risk to enrich", []string{"Info", "Low", "Medium", "High"}, riskIndex(valueOr(cfg.TrafficMinRisk, "medium")))
				switch riskChoice {
				case 1:
					setString(cfg.TrafficMinRisk, "info")
				case 2:
					setString(cfg.TrafficMinRisk, "low")
				case 3:
					setString(cfg.TrafficMinRisk, "medium")
				case 4:
					setString(cfg.TrafficMinRisk, "high")
				}
			}
			if cfg.TrafficTotalMax != nil {
				if *cfg.TrafficTotalMax <= 0 {
					*cfg.TrafficTotalMax = 50
				}
				*cfg.TrafficTotalMax = promptInt(reader, "Global cap on observations", *cfg.TrafficTotalMax)
			}
			if cfg.TrafficMaxBytes != nil {
				*cfg.TrafficMaxBytes = promptInt(reader, "Max bytes per body snippet", *cfg.TrafficMaxBytes)
			}
		}
	}

	if cfg.ScanLabel != nil {
		*cfg.ScanLabel = promptString(reader, "Scan label (appears in INDEX)", *cfg.ScanLabel)
	}
	if cfg.SiteLabel != nil {
		*cfg.SiteLabel = promptString(reader, "Site label override", *cfg.SiteLabel)
	}
	if cfg.ZapBaseURL != nil {
		*cfg.ZapBaseURL = promptString(reader, "ZAP UI base URL (for message links)", *cfg.ZapBaseURL)
	}
	if cfg.RunOut != nil {
		useRunOut := promptYesNo(reader, fmt.Sprintf("Write run artifact JSON to %s?", valueOr(cfg.RunOut, "run.json")), strings.TrimSpace(*cfg.RunOut) != "")
		if useRunOut {
			*cfg.RunOut = promptString(reader, "Run artifact path", valueOr(cfg.RunOut, "out/run.json"))
		} else {
			*cfg.RunOut = ""
		}
	}
	if cfg.ZipOut != nil {
		useZip := promptYesNo(reader, fmt.Sprintf("Bundle outputs into zip (%s)?", valueOr(cfg.ZipOut, "out/kb.zip")), strings.TrimSpace(*cfg.ZipOut) != "")
		if useZip {
			*cfg.ZipOut = promptString(reader, "Zip output path", valueOr(cfg.ZipOut, "out/kb.zip"))
		} else {
			*cfg.ZipOut = ""
		}
	}

	fmt.Println()
	fmt.Println("Wizard setup complete - launching zap-kb with your choices...")
	fmt.Println()
	return nil
}

func chooseOption(reader *bufio.Reader, prompt string, options []string, def int) int {
	if def < 1 || def > len(options) {
		def = 1
	}
	for {
		fmt.Println(prompt + ":")
		for i, opt := range options {
			marker := " "
			if i+1 == def {
				marker = "*"
			}
			fmt.Printf("  %d%s %s\n", i+1, marker, opt)
		}
		fmt.Printf("Select [default %d]: ", def)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		idx, err := strconv.Atoi(line)
		if err == nil && idx >= 1 && idx <= len(options) {
			return idx
		}
		fmt.Println("Invalid choice, please try again.")
	}
}

func promptYesNo(reader *bufio.Reader, prompt string, def bool) bool {
	defChar := "N"
	if def {
		defChar = "Y"
	}
	for {
		fmt.Printf("%s [y/N] (default %s): ", prompt, defChar)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(strings.ToLower(line))
		switch line {
		case "", "y", "yes":
			if line == "" {
				return def
			}
			return true
		case "n", "no":
			return false
		}
		fmt.Println("Please answer y or n.")
	}
}

func promptString(reader *bufio.Reader, prompt string, def string) string {
	fmt.Printf("%s [%s]: ", prompt, def)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptInt(reader *bufio.Reader, prompt string, def int) int {
	for {
		fmt.Printf("%s [%d]: ", prompt, def)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		val, err := strconv.Atoi(line)
		if err == nil {
			return val
		}
		fmt.Println("Enter a whole number, please.")
	}
}

func setString(dst *string, val string) {
	if dst != nil {
		*dst = val
	}
}

func valueOr(ptr *string, fallback string) string {
	if ptr == nil {
		return fallback
	}
	v := strings.TrimSpace(*ptr)
	if v == "" {
		return fallback
	}
	return v
}

func riskIndex(r string) int {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
