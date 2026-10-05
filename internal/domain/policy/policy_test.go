// Package policy_test exercises PolicyRule aggregate invariants.
//
// TDD RED phase. Per CLAUDE.md §1 the Governance domain owns Gatekeeper +
// audit + compliance + IMDA framework. PolicyRule is one of 4 governance
// aggregates.
package policy_test

import (
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	gcidA   = "01970000-0000-7000-9000-000000000001"
)

func TestNew_AssignsUUIDv7RuleID(t *testing.T) {
	t.Parallel()
	r, err := policy.New(policy.NewParams{
		Name:            "no-pii-leakage",
		TenantID:        tenantA,
		EnforcementMode: policy.ModeDeny,
		Conditions: []policy.Condition{
			{Field: "action", Op: policy.OpEquals, Value: "atom.publish"},
		},
	})
	if err != nil {
		t.Fatalf("New() unexpected: %v", err)
	}
	if len(r.RuleID) != 36 {
		t.Errorf("RuleID length = %d; want 36 (UUID)", len(r.RuleID))
	}
	if r.RuleID[14] != '7' {
		t.Errorf("RuleID version char = %q; want '7'", string(r.RuleID[14]))
	}
}

func TestNew_GlobalScopeWhenTenantEmpty(t *testing.T) {
	t.Parallel()
	r, err := policy.New(policy.NewParams{
		Name:            "global-deny",
		TenantID:        "", // global scope
		EnforcementMode: policy.ModeDeny,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "x"}},
	})
	if err != nil {
		t.Fatalf("New() unexpected: %v", err)
	}
	if !r.IsGlobal() {
		t.Errorf("IsGlobal() = false; want true when TenantID empty")
	}
}

func TestNew_StatusDefaultsActive(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "a", Op: policy.OpEquals, Value: "b"}},
	})
	if r.Status != policy.StatusActive {
		t.Errorf("Status = %q; want active", r.Status)
	}
}

func TestNew_StartsAtVersionOne(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "a", Op: policy.OpEquals, Value: "b"}},
	})
	if r.Version != 1 {
		t.Errorf("Version = %d; want 1", r.Version)
	}
}

func TestNew_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	_, err := policy.New(policy.NewParams{
		Name: "  ", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "a", Op: policy.OpEquals, Value: "b"}},
	})
	if err == nil {
		t.Errorf("expected error for empty name; got nil")
	}
}

func TestNew_RejectsInvalidEnforcementMode(t *testing.T) {
	t.Parallel()
	_, err := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: "shrug",
		Conditions: []policy.Condition{{Field: "a", Op: policy.OpEquals, Value: "b"}},
	})
	if err == nil {
		t.Errorf("expected error for invalid enforcement mode; got nil")
	}
}

func TestNew_RejectsEmptyConditions(t *testing.T) {
	t.Parallel()
	_, err := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: nil,
	})
	if err == nil {
		t.Errorf("expected error for missing conditions; got nil")
	}
}

func TestNew_RejectsInvalidConditionOp(t *testing.T) {
	t.Parallel()
	_, err := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "a", Op: "nope", Value: "b"}},
	})
	if err == nil {
		t.Errorf("expected error for invalid op; got nil")
	}
}

func TestNew_AcceptsAllValidEnforcementModes(t *testing.T) {
	t.Parallel()
	for _, m := range []policy.EnforcementMode{policy.ModeAllow, policy.ModeWarn, policy.ModeDeny} {
		_, err := policy.New(policy.NewParams{
			Name: "x", TenantID: tenantA, EnforcementMode: m,
			Conditions: []policy.Condition{{Field: "a", Op: policy.OpEquals, Value: "b"}},
		})
		if err != nil {
			t.Errorf("New(mode=%q) unexpected: %v", m, err)
		}
	}
}

// -----------------------------------------------------------------------------
// Matches — declarative DSL stub
// -----------------------------------------------------------------------------

func TestMatches_EqualsHit(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "atom.create"}},
	})
	ok := r.Matches(map[string]any{"action": "atom.create"})
	if !ok {
		t.Errorf("Matches() = false; want true")
	}
}

func TestMatches_EqualsMiss(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "atom.create"}},
	})
	if r.Matches(map[string]any{"action": "atom.delete"}) {
		t.Errorf("Matches() = true; want false on different value")
	}
}

func TestMatches_NotEquals(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "action", Op: policy.OpNotEquals, Value: "x"}},
	})
	if !r.Matches(map[string]any{"action": "y"}) {
		t.Errorf("not_equals(action=y, value=x) should match")
	}
	if r.Matches(map[string]any{"action": "x"}) {
		t.Errorf("not_equals(action=x, value=x) should not match")
	}
}

func TestMatches_InOperator(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "action", Op: policy.OpIn, Value: []any{"a", "b", "c"}}},
	})
	if !r.Matches(map[string]any{"action": "b"}) {
		t.Errorf("in([a,b,c], b) should match")
	}
	if r.Matches(map[string]any{"action": "z"}) {
		t.Errorf("in([a,b,c], z) should not match")
	}
}

func TestMatches_AllConditionsMustPass_AndSemantics(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{
			{Field: "action", Op: policy.OpEquals, Value: "x"},
			{Field: "resource", Op: policy.OpEquals, Value: "atom"},
		},
	})
	if !r.Matches(map[string]any{"action": "x", "resource": "atom"}) {
		t.Errorf("two-condition AND should match when both pass")
	}
	if r.Matches(map[string]any{"action": "x", "resource": "course"}) {
		t.Errorf("two-condition AND should fail when one fails")
	}
}

func TestMatches_MissingFieldFailsCondition(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "missing", Op: policy.OpEquals, Value: "x"}},
	})
	if r.Matches(map[string]any{}) {
		t.Errorf("missing field should not match")
	}
}

// -----------------------------------------------------------------------------
// Mode validity
// -----------------------------------------------------------------------------

func TestEnforcementMode_Valid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		m  policy.EnforcementMode
		ok bool
	}{
		{policy.ModeAllow, true},
		{policy.ModeWarn, true},
		{policy.ModeDeny, true},
		{policy.EnforcementMode("freeform"), false},
		{policy.EnforcementMode(""), false},
	}
	for _, c := range cases {
		if c.m.Valid() != c.ok {
			t.Errorf("Valid(%q) = %v; want %v", c.m, c.m.Valid(), c.ok)
		}
	}
}

func TestStatus_Valid(t *testing.T) {
	t.Parallel()
	if !policy.StatusActive.Valid() {
		t.Errorf("StatusActive should be valid")
	}
	if !policy.StatusInactive.Valid() {
		t.Errorf("StatusInactive should be valid")
	}
	if policy.Status("nope").Valid() {
		t.Errorf("invalid status should fail")
	}
}

// -----------------------------------------------------------------------------
// IsGlobal scope
// -----------------------------------------------------------------------------

func TestIsGlobal_FalseForTenantScoped(t *testing.T) {
	t.Parallel()
	r, _ := policy.New(policy.NewParams{
		Name: "x", TenantID: tenantA, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "a", Op: policy.OpEquals, Value: "b"}},
	})
	if r.IsGlobal() {
		t.Errorf("tenant-scoped rule should not be global")
	}
	_ = gcidA
}
