package entities

import "testing"

func TestMergeExportPolicyRequiresAgreement(t *testing.T) {
	a := EntitiesFile{SchemaVersion: "v1", ExportPolicy: "native-tool-only-v1"}
	for _, v := range []string{"native-tool-only-v1", "", "external-feed-v1"} {
		b := EntitiesFile{SchemaVersion: "v1", ExportPolicy: v}
		got := Merge(a, b).ExportPolicy
		want := ""
		if v == a.ExportPolicy {
			want = v
		}
		if got != want {
			t.Fatalf("merge %q got %q want %q", v, got, want)
		}
	}
}
