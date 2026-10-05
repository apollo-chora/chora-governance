// Repository_test exercises the InMemoryRepository implementation of the
// PolicyRule persistence port (declared in the same package for hexagonal
// cleanliness and so coverage is attributed to the domain).
package policy_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

const (
	repoTenantA = "01970000-0000-7000-8000-000000000001"
	repoTenantB = "01970000-0000-7000-8000-000000000002"
)

func mustRule(t *testing.T, name, tenant string) *policy.Rule {
	t.Helper()
	r, err := policy.New(policy.NewParams{
		Name: name, TenantID: tenant, EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "a", Op: policy.OpEquals, Value: "b"}},
	})
	if err != nil {
		t.Fatalf("policy.New unexpected: %v", err)
	}
	return r
}

func TestRepo_SaveAndGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := policy.NewInMemoryRepository()
	rule := mustRule(t, "x", repoTenantA)
	if err := r.Save(ctx, rule); err != nil {
		t.Fatalf("Save unexpected: %v", err)
	}
	got, err := r.Get(ctx, rule.RuleID)
	if err != nil {
		t.Fatalf("Get unexpected: %v", err)
	}
	if got.RuleID != rule.RuleID {
		t.Errorf("RuleID mismatch: got %s want %s", got.RuleID, rule.RuleID)
	}
}

func TestRepo_Get_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := policy.NewInMemoryRepository()
	_, err := r.Get(ctx, "nope")
	if err == nil {
		t.Errorf("expected ErrNotFound")
	}
}

func TestRepo_FindApplicable_TenantPlusGlobal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := policy.NewInMemoryRepository()

	tenantRule := mustRule(t, "tenant-only", repoTenantA)
	otherTenantRule := mustRule(t, "other-tenant", repoTenantB)
	globalRule, _ := policy.New(policy.NewParams{
		Name: "global", TenantID: "", EnforcementMode: policy.ModeAllow,
		Conditions: []policy.Condition{{Field: "a", Op: policy.OpEquals, Value: "b"}},
	})

	_ = r.Save(ctx, tenantRule)
	_ = r.Save(ctx, otherTenantRule)
	_ = r.Save(ctx, globalRule)

	applicable, err := r.FindApplicable(ctx, repoTenantA)
	if err != nil {
		t.Fatalf("FindApplicable unexpected: %v", err)
	}
	if len(applicable) != 2 {
		t.Errorf("applicable size = %d; want 2 (tenant + global, NOT other tenant)", len(applicable))
	}
	for _, a := range applicable {
		if a.TenantID != "" && a.TenantID != repoTenantA {
			t.Errorf("FindApplicable returned cross-tenant rule: %v", a)
		}
	}
}

func TestRepo_FindApplicable_SkipsInactive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := policy.NewInMemoryRepository()
	rule := mustRule(t, "x", repoTenantA)
	rule.Status = policy.StatusInactive
	_ = r.Save(ctx, rule)
	out, _ := r.FindApplicable(ctx, repoTenantA)
	if len(out) != 0 {
		t.Errorf("inactive rule should be skipped; got %d", len(out))
	}
}

func TestRepo_List_FilterByTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := policy.NewInMemoryRepository()
	_ = r.Save(ctx, mustRule(t, "a", repoTenantA))
	_ = r.Save(ctx, mustRule(t, "b", repoTenantB))
	out, err := r.List(ctx, policy.ListFilter{TenantID: repoTenantA})
	if err != nil {
		t.Fatalf("List unexpected: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("List(tenantA) size = %d; want 1", len(out))
	}
}

func TestRepo_List_NoTenantReturnsAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := policy.NewInMemoryRepository()
	_ = r.Save(ctx, mustRule(t, "a", repoTenantA))
	_ = r.Save(ctx, mustRule(t, "b", repoTenantB))
	out, _ := r.List(ctx, policy.ListFilter{})
	if len(out) != 2 {
		t.Errorf("List(no filter) size = %d; want 2", len(out))
	}
}

func TestRepo_List_LimitAndOffset(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := policy.NewInMemoryRepository()
	for i := 0; i < 5; i++ {
		_ = r.Save(ctx, mustRule(t, "rule", repoTenantA))
	}
	out, _ := r.List(ctx, policy.ListFilter{TenantID: repoTenantA, Limit: 2})
	if len(out) != 2 {
		t.Errorf("List(limit=2) size = %d; want 2", len(out))
	}
	out2, _ := r.List(ctx, policy.ListFilter{TenantID: repoTenantA, Offset: 100})
	if len(out2) != 0 {
		t.Errorf("List(offset>=len) size = %d; want 0", len(out2))
	}
}
