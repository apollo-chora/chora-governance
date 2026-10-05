// tail_test.go — coverage tail: Condition.matches branches that the main
// suite does not reach (OpIn with a non-slice value, unknown operator).
package policy_test

import (
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

func TestMatches_OpInNonSliceValueDoesNotMatch(t *testing.T) {
	t.Parallel()
	r := &policy.Rule{Conditions: []policy.Condition{
		{Field: "action", Op: policy.OpIn, Value: "not-a-slice"},
	}}
	if r.Matches(map[string]any{"action": "anything"}) {
		t.Error("OpIn with non-slice value must not match")
	}
}

func TestMatches_UnknownOperatorDoesNotMatch(t *testing.T) {
	t.Parallel()
	r := &policy.Rule{Conditions: []policy.Condition{
		{Field: "action", Op: policy.Op("bogus"), Value: "x"},
	}}
	if r.Matches(map[string]any{"action": "x"}) {
		t.Error("unknown op must not match")
	}
}
