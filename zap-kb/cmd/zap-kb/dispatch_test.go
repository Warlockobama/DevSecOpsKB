package main

import "testing"

func TestLookupSubcommand(t *testing.T) {
	handler, args, ok := lookupSubcommand([]string{"merge", "-inputs", "a.json,b.json"})
	if !ok {
		t.Fatal("expected merge to resolve as a subcommand")
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if len(args) != 2 || args[0] != "-inputs" || args[1] != "a.json,b.json" {
		t.Fatalf("unexpected remaining args: %#v", args)
	}
}

func TestLookupSubcommandUnknown(t *testing.T) {
	handler, args, ok := lookupSubcommand([]string{"unknown", "-flag"})
	if ok {
		t.Fatal("expected unknown command to fall through to global flags")
	}
	if handler != nil {
		t.Fatal("expected nil handler")
	}
	if args != nil {
		t.Fatalf("expected nil args, got %#v", args)
	}
}

func TestLookupSubcommandNoArgs(t *testing.T) {
	handler, args, ok := lookupSubcommand(nil)
	if ok {
		t.Fatal("expected no args to fall through")
	}
	if handler != nil {
		t.Fatal("expected nil handler")
	}
	if args != nil {
		t.Fatalf("expected nil args, got %#v", args)
	}
}
