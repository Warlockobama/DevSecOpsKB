//go:build e2e

package harness

import (
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestFixturePassesEntityValidation(t *testing.T) {
	t.Parallel()

	for _, opts := range []FixtureOptions{
		{NumHighFindings: 1},
		{NumHighFindings: 2, Secret: "Bearer fixture-secret"},
	} {
		if result := entities.Validate(Fixture(opts)); !result.OK() {
			t.Fatalf("generated fixture is invalid: %v", result.Issues)
		}
	}
}
