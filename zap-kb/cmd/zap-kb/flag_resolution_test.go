package main

import (
	"flag"
	"testing"
	"time"
)

func TestSuppliedFlagsPreservesFalseZeroDurationAndEmpty(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var enabled bool
	var limit int
	var timeout time.Duration
	var value string
	fs.BoolVar(&enabled, "enabled", true, "")
	fs.IntVar(&limit, "limit", 12, "")
	fs.DurationVar(&timeout, "timeout", time.Minute, "")
	fs.StringVar(&value, "value", "default", "")
	if err := fs.Parse([]string{"-enabled=false", "-limit=0", "-timeout=0", "-value="}); err != nil {
		t.Fatal(err)
	}
	supplied := suppliedFlags(fs)
	for _, name := range []string{"enabled", "limit", "timeout", "value"} {
		if !supplied[name] {
			t.Fatalf("%s should be recorded as supplied", name)
		}
	}
	if enabled || limit != 0 || timeout != 0 || value != "" {
		t.Fatalf("flag values were not preserved: enabled=%v limit=%d timeout=%s value=%q", enabled, limit, timeout, value)
	}
}

func TestResolveStringFlagEnvDefaultPrecedence(t *testing.T) {
	env := fakeEnv(map[string]string{"SETTING": "environment"})
	if value, source := resolveStringFlagEnvDefault("explicit", true, "SETTING", "default", env); value != "explicit" || source != "flag" {
		t.Fatalf("explicit value mismatch: %q from %q", value, source)
	}
	if value, source := resolveStringFlagEnvDefault("", true, "SETTING", "default", env); value != "" || source != "flag" {
		t.Fatalf("explicit empty mismatch: %q from %q", value, source)
	}
	if value, source := resolveStringFlagEnvDefault("default", false, "SETTING", "default", env); value != "environment" || source != "env:SETTING" {
		t.Fatalf("environment value mismatch: %q from %q", value, source)
	}
	if value, source := resolveStringFlagEnvDefault("default", false, "SETTING", "default", fakeEnv(nil)); value != "default" || source != "default" {
		t.Fatalf("default value mismatch: %q from %q", value, source)
	}
}
