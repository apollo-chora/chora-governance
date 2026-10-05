// tail_test.go — coverage tail: Dimension.Valid's deprecated-alias accept
// branch + the false branches.
package imda_test

import (
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

func TestDimension_Valid_DeprecatedAliasAccepted(t *testing.T) {
	t.Parallel()
	if !imda.Dimension("risk_levels").Valid() {
		t.Error("deprecated alias risk_levels should be Valid")
	}
}

func TestDimension_Valid_InvalidValuesRejected(t *testing.T) {
	t.Parallel()
	if imda.Dimension("bogus").Valid() {
		t.Error("arbitrary dimension must not be Valid")
	}
	if imda.Dimension("").Valid() {
		t.Error("empty dimension must not be Valid")
	}
}
