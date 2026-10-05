package pg

import (
	"context"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

// policy_rules is RLS-protected: its live policy is
//
//	FOR ALL USING (tenant_id IS NULL OR tenant_id = current_setting('chora.tenant_id', true)::uuid)
//
// with a NULL with_check, so PostgreSQL applies that USING expression as the
// WITH CHECK on INSERT. Saving a PER-TENANT rule on a bare pool therefore
// evaluates current_setting to NULL, fails the check and raises 42501. It has
// never fired because policy_rules holds ZERO rows in production: the table has
// never taken a row, so the fault has stayed latent exactly the way audit_log's
// did until a real message finally arrived.
//
// A platform-global rule (empty tenant) is unaffected, since tenant_id IS NULL
// satisfies the policy on its own. The regression is specifically the first
// tenant-scoped rule anyone saves.
func TestPolicySave_EstablishesTenantContextForATenantScopedRule(t *testing.T) {
	q := &recordingTenantQuerier{}
	repo := NewPolicyRepository(q)

	err := repo.Save(context.Background(), &policy.Rule{
		RuleID:   "8f14e45f-ceea-467a-9c1a-000000000001",
		TenantID: "11111111-1111-7111-8111-111111111111",
		Name:     "deny-egress",
		Version:  1,
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if q.tenantUsed == "" {
		t.Fatal("Save wrote without establishing tenant context; a tenant-scoped rule would be RLS-rejected with 42501")
	}
	if q.tenantUsed != "11111111-1111-7111-8111-111111111111" {
		t.Errorf("tenant context = %q, want the rule's own tenant", q.tenantUsed)
	}
	if !strings.Contains(q.sql, "INSERT INTO policy_rules") {
		t.Errorf("unexpected statement: %q", q.sql)
	}
}

// A platform-global rule must keep working, and must be scoped to the canonical
// nil-tenant rather than left unscoped.
func TestPolicySave_GlobalRuleStillSaves(t *testing.T) {
	q := &recordingTenantQuerier{}
	repo := NewPolicyRepository(q)

	if err := repo.Save(context.Background(), &policy.Rule{
		RuleID: "8f14e45f-ceea-467a-9c1a-000000000002",
		Name:   "platform-default",
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if q.tenantUsed != NilTenantUUID {
		t.Errorf("global rule tenant context = %q, want the canonical nil tenant %q", q.tenantUsed, NilTenantUUID)
	}
}

// recordingTenantQuerier is a TenantTxQuerier that records which tenant the
// write was scoped to. A bare Exec (no WithTenantTx) leaves tenantUsed empty,
// which is exactly the 42501 shape under test.
type recordingTenantQuerier struct {
	tenantUsed string
	sql        string
}

func (q *recordingTenantQuerier) Exec(_ context.Context, sql string, _ ...any) error {
	q.sql = sql
	return nil
}
func (q *recordingTenantQuerier) QueryRow(_ context.Context, _ string, _ ...any) Row { return nil }
func (q *recordingTenantQuerier) Query(_ context.Context, _ string, _ ...any) (Rows, error) {
	return nil, nil
}
func (q *recordingTenantQuerier) WithTenantTx(
	ctx context.Context, tenantID string, fn func(context.Context, TenantScopedQuerier) error,
) error {
	q.tenantUsed = tenantID
	return fn(ctx, q)
}
