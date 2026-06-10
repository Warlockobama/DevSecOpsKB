//go:build e2e

package forgejoe2e

import "github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"

// withTicketRef returns a (possibly new) Analyst with ref appended to its
// TicketRefs — fixture plumbing for pull tests.
func withTicketRef(a *entities.Analyst, ref string) *entities.Analyst {
	if a == nil {
		a = &entities.Analyst{}
	}
	a.TicketRefs = append(a.TicketRefs, ref)
	return a
}
