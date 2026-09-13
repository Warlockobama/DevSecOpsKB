package publication

import "testing"

func TestRequiredZeroAttemptFailureAndPartialOutcome(t *testing.T) {
	for _, status := range []Status{Failed, Partial} {
		r := Result{Stages: []StageResult{{Destination: "jira", Stage: "configuration", Required: true, Status: status}, {Destination: "confluence", Stage: "publish", Required: true, Status: Successful}}}
		if r.Err() == nil {
			t.Fatal("required failure hidden by unrelated success or zero attempts")
		}
	}
	if (Result{Stages: []StageResult{{Required: true, Status: Skipped}}}).Err() != nil {
		t.Fatal("deliberate skip failed")
	}
	if Outcome(0, 1, 1) != Partial || Outcome(0, 0, 1) != Failed || Outcome(0, 2, 0) != Successful {
		t.Fatal("incorrect no-op/partial classification")
	}
}
