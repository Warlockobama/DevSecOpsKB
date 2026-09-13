package main

import (
	"flag"
	"strings"
)

// suppliedFlags records presence, independently from a flag's final value.
// This preserves deliberate -flag=false, -limit=0, and -value="" choices.
func suppliedFlags(fs *flag.FlagSet) map[string]bool {
	supplied := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		supplied[f.Name] = true
	})
	return supplied
}

// resolveStringFlagEnvDefault applies the CLI's configuration contract: an
// explicit flag always wins, then a non-blank environment value, then default.
// The returned source is safe to include in diagnostics because it contains no
// setting value.
func resolveStringFlagEnvDefault(flagValue string, flagSet bool, envKey, defaultValue string, getenv func(string) string) (string, string) {
	if flagSet {
		return strings.TrimSpace(flagValue), "flag"
	}
	if value := strings.TrimSpace(getenv(envKey)); value != "" {
		return value, "env:" + envKey
	}
	return defaultValue, "default"
}
