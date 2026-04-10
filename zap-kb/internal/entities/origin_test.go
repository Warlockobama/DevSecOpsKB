package entities

import "testing"

func TestDefinitionOriginValue(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		pluginID string
		det      *Detection
		want     string
	}{
		{name: "explicit tool", origin: DefinitionOriginTool, pluginID: "10001", want: DefinitionOriginTool},
		{name: "explicit custom", origin: DefinitionOriginCustom, pluginID: "10001", want: DefinitionOriginCustom},
		{name: "numeric plugin defaults to tool", pluginID: "10001", want: DefinitionOriginTool},
		{name: "zap custom plugin prefix", pluginID: "zap-authz-rule", want: DefinitionOriginCustom},
		{name: "custom detection source", pluginID: "10001", det: &Detection{RuleSource: "custom"}, want: DefinitionOriginCustom},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DefinitionOriginValue(tc.origin, tc.pluginID, tc.det); got != tc.want {
				t.Fatalf("DefinitionOriginValue() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMerge_PreservesAndNormalizesDefinitionOrigin(t *testing.T) {
	base := EntitiesFile{
		SchemaVersion: "1",
		Definitions:   []Definition{{DefinitionID: "def-10001", PluginID: "10001"}},
	}
	add := EntitiesFile{
		SchemaVersion: "1",
		Definitions: []Definition{
			{DefinitionID: "def-10001", PluginID: "10001", Origin: DefinitionOriginTool},
			{DefinitionID: "def-zap-custom", PluginID: "zap-custom-rule"},
		},
	}
	merged := Merge(base, add)
	if got := merged.Definitions[0].Origin; got != DefinitionOriginTool {
		t.Fatalf("merged existing definition origin = %q, want %q", got, DefinitionOriginTool)
	}
	if got := merged.Definitions[1].Origin; got != DefinitionOriginCustom {
		t.Fatalf("merged new definition origin = %q, want %q", got, DefinitionOriginCustom)
	}
}

func TestNormalizeDefinitionOrigins_DefaultsScannerSourcesToTool(t *testing.T) {
	ef := EntitiesFile{
		SourceTool: "zap",
		Definitions: []Definition{
			{DefinitionID: "def-zap-authenticated-basket-item-enumeration", PluginID: "zap-authenticated-basket-item-enumeration"},
			{DefinitionID: "def-custom", PluginID: "zap-custom-rule", Origin: DefinitionOriginCustom},
		},
	}

	NormalizeDefinitionOrigins(&ef)

	if got := ef.Definitions[0].Origin; got != DefinitionOriginTool {
		t.Fatalf("scanner-backed normalized plugin origin = %q, want %q", got, DefinitionOriginTool)
	}
	if got := ef.Definitions[1].Origin; got != DefinitionOriginCustom {
		t.Fatalf("explicit custom origin = %q, want %q", got, DefinitionOriginCustom)
	}
}
