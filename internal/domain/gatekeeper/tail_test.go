// tail_test.go — coverage tail: the Evaluator's defensive inactive-rule skip
// (reachable only when the repository returns inactive rules, which the
// in-memory FindApplicable never does).
package gatekeeper_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

// inactiveReturningRepo bypasses the InMemoryRepository's inactive-rule
// filtering so the Evaluator's own Status check is exercised.
type inactiveReturningRepo struct {
	*policy.InMemoryRepository
}

func (r *inactiveReturningRepo) FindApplicable(ctx context.Context, tenantID string) ([]*policy.Rule, error) {
	rules, err := r.InMemoryRepository.List(ctx, policy.ListFilter{TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	out := make([]*policy.Rule, 0, len(rules))
	for _, rl := range rules {
		if rl.IsGlobal() || rl.TenantID == tenantID {
			out = append(out, rl)
		}
	}
	return out, nil
}

func TestEvaluate_SkipsInactiveRulesDefensively(t *testing.T) {
	t.Parallel()
	repo := policy.NewInMemoryRepository()
	rule, err := policy.New(policy.NewParams{
		Name: "retired", TenantID: "t1", EnforcementMode: policy.ModeDeny,
		Conditions: []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "write"}},
	})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	rule.Status = policy.StatusInactive
	if err := repo.Save(context.Background(), rule); err != nil {
		t.Fatalf("Save: %v", err)
	}

	auditRepo := audit.NewInMemoryRepository()
	eval := gatekeeper.NewEvaluator(&inactiveReturningRepo{repo}, auditRepo)
	d, err := eval.Evaluate(context.Background(), gatekeeper.Request{
		TenantID: "t1", Gcid: "g1", Action: "write",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted (inactive deny rule must be skipped)", d.Decision)
	}
}
