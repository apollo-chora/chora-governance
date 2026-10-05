// audit_repository_rls_test.go — RLS routing for audit_log (CHO-2245 follow-up).
//
// audit_log carries `tenant_isolation FOR ALL USING (tenant_id =
// current_setting('chora.tenant_id', true)::uuid)` (migration 0001). Writes on
// the BARE pool (no SET LOCAL chora.tenant_id) are rejected 42501; reads
// silently return zero rows. AuditRepository must therefore route every
// access through TenantTxQuerier.WithTenantTx — the same idiom evidence /
// imda repos use.
//
// These tests use a fake that DISCRIMINATES bare-pool calls from calls made
// inside WithTenantTx, so they prove: (a) Append runs the chain-head SELECT AND
// the INSERT inside ONE tenant-scoped tx; (b) Query scopes to f.TenantID (empty
// → NilTenant, mirroring evidence rlsScopeFilter); (c) GetByID scopes too.
package pg_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

// rlsRecorder is a TenantTxQuerier that records the tenant a repo scopes each
// transaction to, plus which ops ran INSIDE WithTenantTx vs on the bare pool.
// bareOps must stay empty for RLS-protected tables.
type rlsRecorder struct {
	txEntered bool
	txTenant  string
	inTxOps   []string
	bareOps   []string
	headHash  string // chain-head QueryRow value ("" ⇒ genesis / ErrNoRows)
	execErr   error
}

func (q *rlsRecorder) Exec(_ context.Context, _ string, _ ...any) error {
	q.bareOps = append(q.bareOps, "exec")
	return q.execErr
}

func (q *rlsRecorder) QueryRow(_ context.Context, _ string, _ ...any) pg.Row {
	q.bareOps = append(q.bareOps, "queryrow")
	return q.headRow()
}

func (q *rlsRecorder) Query(_ context.Context, _ string, _ ...any) (pg.Rows, error) {
	q.bareOps = append(q.bareOps, "query")
	return &stubRows{}, nil
}

func (q *rlsRecorder) WithTenantTx(ctx context.Context, tenantID string, fn func(context.Context, pg.TenantScopedQuerier) error) error {
	q.txEntered = true
	q.txTenant = tenantID
	return fn(ctx, &rlsRecorderTx{parent: q})
}

func (q *rlsRecorder) headRow() pg.Row {
	if q.headHash == "" {
		return &stubRow{err: pg.ErrNoRows}
	}
	h := q.headHash
	return &stubRow{scan: func(dest ...any) error {
		if p, ok := dest[0].(*string); ok {
			*p = h
		}
		return nil
	}}
}

type rlsRecorderTx struct{ parent *rlsRecorder }

func (t *rlsRecorderTx) Exec(_ context.Context, _ string, _ ...any) error {
	t.parent.inTxOps = append(t.parent.inTxOps, "exec")
	return t.parent.execErr
}

func (t *rlsRecorderTx) QueryRow(_ context.Context, _ string, _ ...any) pg.Row {
	t.parent.inTxOps = append(t.parent.inTxOps, "queryrow")
	return t.parent.headRow()
}

func (t *rlsRecorderTx) Query(_ context.Context, _ string, _ ...any) (pg.Rows, error) {
	t.parent.inTxOps = append(t.parent.inTxOps, "query")
	return &stubRows{}, nil
}

func TestAuditRepository_Append_RoutesHeadAndInsertThroughOneTenantTx(t *testing.T) {
	t.Parallel()
	e := newEvent(t)
	q := &rlsRecorder{}
	repo := pg.NewAuditRepository(q)

	if err := repo.Append(context.Background(), e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !q.txEntered {
		t.Fatalf("Append must run inside WithTenantTx (audit_log RLS tenant_isolation); ran on bare pool")
	}
	if q.txTenant != e.TenantID {
		t.Errorf("SET LOCAL chora.tenant_id = %q; want the event tenant %q", q.txTenant, e.TenantID)
	}
	if len(q.bareOps) != 0 {
		t.Errorf("no op may run on the bare pool (RLS-unsafe); got %v", q.bareOps)
	}
	// BOTH statements (chain-head SELECT, then INSERT) inside the ONE tx.
	if len(q.inTxOps) != 2 || q.inTxOps[0] != "queryrow" || q.inTxOps[1] != "exec" {
		t.Errorf("in-tx ops = %v; want [queryrow exec] (head lookup + insert in ONE tenant tx)", q.inTxOps)
	}
}

func TestAuditRepository_Query_RoutesThroughTenantTx(t *testing.T) {
	t.Parallel()
	tenant := uuid.NewString()
	q := &rlsRecorder{}
	repo := pg.NewAuditRepository(q)

	if _, err := repo.Query(context.Background(), audit.QueryFilter{TenantID: tenant, Action: "external_egress"}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !q.txEntered || q.txTenant != tenant {
		t.Fatalf("Query must SET LOCAL chora.tenant_id=%q; entered=%v tenant=%q", tenant, q.txEntered, q.txTenant)
	}
	if len(q.bareOps) != 0 {
		t.Errorf("no op may run on the bare pool; got %v", q.bareOps)
	}
}

// Empty-tenant read mirrors evidence rlsScopeFilter: scope to NilTenant
// (platform) — never a GUC-less bare read that would silently return 0 rows.
func TestAuditRepository_Query_EmptyTenant_ScopesToNilTenant(t *testing.T) {
	t.Parallel()
	q := &rlsRecorder{}
	repo := pg.NewAuditRepository(q)

	if _, err := repo.Query(context.Background(), audit.QueryFilter{}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if q.txTenant != pg.NilTenantUUID {
		t.Errorf("empty-tenant Query scope = %q; want NilTenantUUID %q", q.txTenant, pg.NilTenantUUID)
	}
}

func TestAuditRepository_GetByID_ScopesToTenantTx(t *testing.T) {
	t.Parallel()
	q := &rlsRecorder{}
	repo := pg.NewAuditRepository(q)

	_, _ = repo.GetByID(context.Background(), uuid.NewString()) // no row → ErrNotFound; assert the scope
	if !q.txEntered {
		t.Fatalf("GetByID must run inside WithTenantTx (audit_log RLS)")
	}
	if q.txTenant != pg.NilTenantUUID {
		t.Errorf("GetByID scope = %q; want NilTenantUUID %q (no tenant param → platform scope)", q.txTenant, pg.NilTenantUUID)
	}
	if len(q.bareOps) != 0 {
		t.Errorf("no op may run on the bare pool; got %v", q.bareOps)
	}
}
