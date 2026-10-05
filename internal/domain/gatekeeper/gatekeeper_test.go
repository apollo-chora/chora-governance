// Package gatekeeper_test — exercises the Gatekeeper evaluation domain logic.
//
// Per the spec:
//   - Gatekeeper evaluate emits AuditEvent on every call (allow OR deny — both
//     audited).
//   - PolicyRule deny overrides allow when both match (priority by
//     enforcement_mode).
//
// The gatekeeper depends on the policy + audit packages.
package gatekeeper_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	gcidA   = "01970000-0000-7000-9000-000000000001"
)

func setupEvaluator(t *testing.T, rules ...*policy.Rule) *gatekeeper.Evaluator {
	t.Helper()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	ctx := context.Background()
	for _, r := range rules {
		if err := policyRepo.Save(ctx, r); err != nil {
			t.Fatalf("seed policy: %v", err)
		}
	}
	return gatekeeper.NewEvaluator(policyRepo, auditRepo)
}

// -----------------------------------------------------------------------------
// Default behaviour: no rules -> implicit allow + audit
// -----------------------------------------------------------------------------

func TestEvaluate_NoRules_DefaultsToAllow(t *testing.T) {
	t.Parallel()
	ev := setupEvaluator(t)
	ctx := context.Background()
	d, err := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA,
		Action: "atom.create", Resource: "learningatom",
	})
	if err != nil {
		t.Fatalf("Evaluate unexpected: %v", err)
	}
	if d.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted (default-allow when no rules match)", d.Decision)
	}
}

// -----------------------------------------------------------------------------
// Always-audit invariant
// -----------------------------------------------------------------------------

func TestEvaluate_AlwaysEmitsAuditEvent_OnPermit(t *testing.T) {
	t.Parallel()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	ev := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	ctx := context.Background()

	_, err := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA,
		Action: "atom.create", Resource: "learningatom",
	})
	if err != nil {
		t.Fatalf("Evaluate unexpected: %v", err)
	}
	out, _ := auditRepo.Query(ctx, audit.QueryFilter{TenantID: tenantA})
	if len(out) != 1 {
		t.Errorf("expected 1 audit event after permit; got %d", len(out))
	}
	if len(out) > 0 && out[0].Decision != audit.DecisionPermitted {
		t.Errorf("audit event Decision = %q; want permitted", out[0].Decision)
	}
}

func TestEvaluate_AlwaysEmitsAuditEvent_OnDeny(t *testing.T) {
	t.Parallel()
	denyRule, _ := policy.New(policy.NewParams{
		Name: "deny-publish", TenantID: tenantA,
		EnforcementMode: policy.ModeDeny,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "atom.publish"}},
	})
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	ev := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	ctx := context.Background()
	_ = policyRepo.Save(ctx, denyRule)

	_, err := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA,
		Action: "atom.publish", Resource: "learningatom",
	})
	if err != nil {
		t.Fatalf("Evaluate unexpected: %v", err)
	}
	out, _ := auditRepo.Query(ctx, audit.QueryFilter{TenantID: tenantA})
	if len(out) != 1 {
		t.Errorf("expected 1 audit event after deny; got %d", len(out))
	}
	if len(out) > 0 && out[0].Decision != audit.DecisionDenied {
		t.Errorf("audit event Decision = %q; want denied", out[0].Decision)
	}
}

// -----------------------------------------------------------------------------
// Deny overrides allow — rule priority by enforcement_mode
// -----------------------------------------------------------------------------

func TestEvaluate_DenyOverridesAllow_WhenBothMatch(t *testing.T) {
	t.Parallel()
	allow, _ := policy.New(policy.NewParams{
		Name: "allow-x", TenantID: tenantA,
		EnforcementMode: policy.ModeAllow,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "atom.publish"}},
	})
	deny, _ := policy.New(policy.NewParams{
		Name: "deny-x", TenantID: tenantA,
		EnforcementMode: policy.ModeDeny,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "atom.publish"}},
	})
	ev := setupEvaluator(t, allow, deny)
	ctx := context.Background()
	d, _ := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA,
		Action: "atom.publish", Resource: "x",
	})
	if d.Decision != audit.DecisionDenied {
		t.Errorf("Decision = %q; want denied (deny overrides allow)", d.Decision)
	}
}

func TestEvaluate_DenyOverridesAllow_RegardlessOfInsertionOrder(t *testing.T) {
	t.Parallel()
	deny, _ := policy.New(policy.NewParams{
		Name: "deny-first", TenantID: tenantA,
		EnforcementMode: policy.ModeDeny,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "x"}},
	})
	allow, _ := policy.New(policy.NewParams{
		Name: "allow-second", TenantID: tenantA,
		EnforcementMode: policy.ModeAllow,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "x"}},
	})
	// Reverse insertion: deny then allow.
	ev := setupEvaluator(t, deny, allow)
	ctx := context.Background()
	d, _ := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA, Action: "x", Resource: "r",
	})
	if d.Decision != audit.DecisionDenied {
		t.Errorf("Decision = %q; want denied even if inserted before allow", d.Decision)
	}
}

func TestEvaluate_OnlyAllowMatched_PermitsAndAudits(t *testing.T) {
	t.Parallel()
	allow, _ := policy.New(policy.NewParams{
		Name: "allow-only", TenantID: tenantA,
		EnforcementMode: policy.ModeAllow,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "x"}},
	})
	ev := setupEvaluator(t, allow)
	ctx := context.Background()
	d, _ := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA, Action: "x", Resource: "r",
	})
	if d.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted", d.Decision)
	}
	if len(d.MatchedRules) != 1 {
		t.Errorf("MatchedRules size = %d; want 1", len(d.MatchedRules))
	}
}

// -----------------------------------------------------------------------------
// Warn — emits audit but permits
// -----------------------------------------------------------------------------

func TestEvaluate_WarnPermitsButFlags(t *testing.T) {
	t.Parallel()
	warn, _ := policy.New(policy.NewParams{
		Name: "warn-x", TenantID: tenantA,
		EnforcementMode: policy.ModeWarn,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "x"}},
	})
	ev := setupEvaluator(t, warn)
	ctx := context.Background()
	d, _ := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA, Action: "x", Resource: "r",
	})
	if d.Decision != audit.DecisionPermitted {
		t.Errorf("warn should permit; got %q", d.Decision)
	}
	if !d.Warned {
		t.Errorf("Warned = false; want true under warn rule")
	}
}

// -----------------------------------------------------------------------------
// Global vs tenant scope
// -----------------------------------------------------------------------------

func TestEvaluate_GlobalRuleAppliesToAllTenants(t *testing.T) {
	t.Parallel()
	deny, _ := policy.New(policy.NewParams{
		Name: "global-deny", TenantID: "", // global
		EnforcementMode: policy.ModeDeny,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "atom.publish"}},
	})
	ev := setupEvaluator(t, deny)
	ctx := context.Background()
	for _, tid := range []string{tenantA, "01970000-0000-7000-8000-000000000002"} {
		d, _ := ev.Evaluate(ctx, gatekeeper.Request{
			TenantID: tid, Gcid: gcidA,
			Action: "atom.publish", Resource: "x",
		})
		if d.Decision != audit.DecisionDenied {
			t.Errorf("tenant %q: Decision = %q; want denied (global rule)", tid, d.Decision)
		}
	}
}

func TestEvaluate_TenantScopedRuleDoesNotApplyToOtherTenants(t *testing.T) {
	t.Parallel()
	tenantB := "01970000-0000-7000-8000-000000000002"
	deny, _ := policy.New(policy.NewParams{
		Name: "tenantA-deny", TenantID: tenantA,
		EnforcementMode: policy.ModeDeny,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "x"}},
	})
	ev := setupEvaluator(t, deny)
	ctx := context.Background()
	d, _ := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantB, Gcid: gcidA, Action: "x", Resource: "r",
	})
	if d.Decision != audit.DecisionPermitted {
		t.Errorf("tenantB should not be denied by tenantA rule; got %q", d.Decision)
	}
}

// -----------------------------------------------------------------------------
// Inactive policies are ignored
// -----------------------------------------------------------------------------

func TestEvaluate_IgnoresInactivePolicies(t *testing.T) {
	t.Parallel()
	deny, _ := policy.New(policy.NewParams{
		Name: "deny-inactive", TenantID: tenantA,
		EnforcementMode: policy.ModeDeny,
		Conditions:      []policy.Condition{{Field: "action", Op: policy.OpEquals, Value: "x"}},
	})
	deny.Status = policy.StatusInactive
	ev := setupEvaluator(t, deny)
	ctx := context.Background()
	d, _ := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA, Action: "x", Resource: "r",
	})
	if d.Decision != audit.DecisionPermitted {
		t.Errorf("inactive deny rule should be ignored; got %q", d.Decision)
	}
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

func TestEvaluate_RejectsMissingTenantID(t *testing.T) {
	t.Parallel()
	ev := setupEvaluator(t)
	ctx := context.Background()
	_, err := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: "", Gcid: gcidA, Action: "x", Resource: "r",
	})
	if err == nil {
		t.Errorf("expected error for missing TenantID; got nil")
	}
}

func TestEvaluate_RejectsMissingAction(t *testing.T) {
	t.Parallel()
	ev := setupEvaluator(t)
	ctx := context.Background()
	_, err := ev.Evaluate(ctx, gatekeeper.Request{
		TenantID: tenantA, Gcid: gcidA, Action: "", Resource: "r",
	})
	if err == nil {
		t.Errorf("expected error for missing Action; got nil")
	}
}
