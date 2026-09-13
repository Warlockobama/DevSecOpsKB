package buildinfo

import "testing"

func TestStringIncludesAllIdentityFields(t *testing.T) {
	oldVersion, oldRevision, oldBuildTime := Version, Revision, BuildTime
	t.Cleanup(func() {
		Version, Revision, BuildTime = oldVersion, oldRevision, oldBuildTime
	})
	Version, Revision, BuildTime = "v1.2.3", "abc123", "2026-09-12T00:00:00Z"

	const want = "zap-kb version=v1.2.3 revision=abc123 build_time=2026-09-12T00:00:00Z"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
