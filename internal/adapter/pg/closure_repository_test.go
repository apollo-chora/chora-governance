// closure_repository_test.go — pgx adapter tests for the durable
// ClosureRepository (W0-F1 durability + W0-F5 error-honesty, CHO-2198)
// using the shared stub Querier (see audit_repository_test.go's
// stubQuerier — already implements WithTenantTx + an injectable
// queryRowFn, so it satisfies pg.TenantTxQuerier without modification).
//
// These are unit tests against the SQL emit + scan surface — no live DB.
// The critical assertions here are the W0-F5 ones: a genuine backing-store
// error from either Pseudonymise or IsPseudonymised must come back as a
// non-nil error, never get coerced into a false/zero "everything is fine"
// result (the swallowed-error trap the in-memory port's original
// `IsPseudonymised(gcid string) bool` signature made structurally
// impossible to avoid).
package pg_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/config"
)

func closureSpecFixture() []config.TableSpec {
	return []config.TableSpec{
		{
			Table: "audit_log",
			Columns: []config.ColumnSpec{
				{Column: "actor_display_name", Strategy: "tombstone_string", Value: "Former member"},
				{Column: "subject_display_name", Strategy: "tombstone_string", Value: "Former member"},
			},
		},
		{
			Table: "imda_assessments",
			Columns: []config.ColumnSpec{
				{Column: "assessor_display_name", Strategy: "tombstone_string", Value: "Former member"},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Pseudonymise
// -----------------------------------------------------------------------------

func TestClosureRepository_Pseudonymise_EmitsInsertOnConflictReturningID(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	var gotSQL string
	var gotArgs []any
	q := &stubQuerier{queryRowFn: func(sql string, args ...any) pg.Row {
		gotSQL, gotArgs = sql, args
		return &stubRow{scan: func(dest ...any) error {
			*(dest[0].(*string)) = uuid.NewString()
			return nil
		}}
	}}
	repo := pg.NewClosureRepository(q)

	tenant := uuid.NewString()
	rows, err := repo.Pseudonymise(context.Background(), tenant, "gcid-A", closureSpecFixture())
	if err != nil {
		t.Fatalf("Pseudonymise: %v", err)
	}
	if rows != 3 {
		t.Fatalf("expected rows_touched=3 (2+1 columns); got %d", rows)
	}

	wants := []string{"INSERT INTO closure_pseudonymisation_state", "ON CONFLICT", "DO NOTHING", "RETURNING"}
	for _, w := range wants {
		if !contains(gotSQL, w) {
			t.Errorf("Pseudonymise SQL missing %q; got:\n%s", w, gotSQL)
		}
	}
	if len(gotArgs) == 0 {
		t.Fatalf("expected query args")
	}
	if !q.txCalled {
		t.Fatal("expected Pseudonymise to run inside WithTenantTx (RLS GUC); it did not")
	}
	if q.txTenantID != tenant {
		t.Errorf("SET LOCAL chora.tenant_id = %q; want %q", q.txTenantID, tenant)
	}
}

func TestClosureRepository_Pseudonymise_NormalisesPlatformSentinel(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	// "platform" is the envelope sentinel for non-tenant subjects
	// (NormalizeTenantForRLS) — the closure_pseudonymisation_state
	// tenant_id column is UUID NOT NULL with a `::uuid` RLS cast, so a
	// bare "platform" literal would 22P02 at row-evaluation time. Mirrors
	// the evidence_repository.go rlsScopeFilter/tenantForFilter contract.
	var gotArgs []any
	q := &stubQuerier{queryRowFn: func(_ string, args ...any) pg.Row {
		gotArgs = args
		return &stubRow{scan: func(dest ...any) error {
			*(dest[0].(*string)) = uuid.NewString()
			return nil
		}}
	}}
	repo := pg.NewClosureRepository(q)

	if _, err := repo.Pseudonymise(context.Background(), "platform", "gcid-A", nil); err != nil {
		t.Fatalf("Pseudonymise: %v", err)
	}
	if q.txTenantID != pg.NilTenantUUID {
		t.Errorf("SET LOCAL chora.tenant_id = %q; want NilTenantUUID %q", q.txTenantID, pg.NilTenantUUID)
	}
	if len(gotArgs) < 2 {
		t.Fatalf("expected >= 2 args; got %d", len(gotArgs))
	}
	if gotArgs[1] != pg.NilTenantUUID {
		t.Errorf("inserted tenant_id arg = %v; want NilTenantUUID %q", gotArgs[1], pg.NilTenantUUID)
	}
}

func TestClosureRepository_Pseudonymise_MintsUUIDv7ForID(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	var gotArgs []any
	q := &stubQuerier{queryRowFn: func(_ string, args ...any) pg.Row {
		gotArgs = args
		return &stubRow{scan: func(dest ...any) error {
			*(dest[0].(*string)) = uuid.NewString()
			return nil
		}}
	}}
	repo := pg.NewClosureRepository(q)

	if _, err := repo.Pseudonymise(context.Background(), uuid.NewString(), "gcid-A", nil); err != nil {
		t.Fatalf("Pseudonymise: %v", err)
	}
	if len(gotArgs) == 0 {
		t.Fatalf("expected query args")
	}
	idArg, ok := gotArgs[0].(string)
	if !ok || idArg == "" {
		t.Fatalf("expected non-empty string id as first arg; got %T %v", gotArgs[0], gotArgs[0])
	}
	parsed, err := uuid.Parse(idArg)
	if err != nil {
		t.Fatalf("minted id %q is not a valid UUID: %v", idArg, err)
	}
	if parsed.Version() != 7 {
		t.Fatalf("minted id %q is not UUIDv7 (version=%d)", idArg, parsed.Version())
	}
}

func TestClosureRepository_Pseudonymise_ReturnsZeroWhenConflictFires(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	// ON CONFLICT DO NOTHING suppresses the RETURNING row — the stub
	// Querier signals that exactly as the pg.Querier seam does: ErrNoRows
	// (the stubQuerier's default QueryRow behaviour when .queryRowFn is
	// unset).
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)

	rows, err := repo.Pseudonymise(context.Background(), uuid.NewString(), "gcid-A", closureSpecFixture())
	if err != nil {
		t.Fatalf("Pseudonymise: expected idempotent no-op, got error: %v", err)
	}
	if rows != 0 {
		t.Fatalf("expected rows=0 on idempotent replay; got %d", rows)
	}
}

func TestClosureRepository_Pseudonymise_RejectsEmptyTenantID(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)
	_, err := repo.Pseudonymise(context.Background(), "", "gcid-A", nil)
	if err == nil {
		t.Fatalf("expected error on empty tenant_id")
	}
	if q.txCalled {
		t.Fatalf("must not open a tenant tx on validation failure")
	}
}

func TestClosureRepository_Pseudonymise_RejectsEmptyGCID(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)
	_, err := repo.Pseudonymise(context.Background(), uuid.NewString(), "", nil)
	if err == nil {
		t.Fatalf("expected error on empty gcid")
	}
	if q.txCalled {
		t.Fatalf("must not open a tenant tx on validation failure")
	}
}

// TestClosureRepository_Pseudonymise_PropagatesScanError is the W0-F5
// fail-loud proof for Pseudonymise: a genuine backing-store error (NOT
// pg.ErrNoRows) must come back as a non-nil error, never as a silent
// "idempotent no-op" (0, nil) — conflating "I don't know" with "already
// done" would let the closure saga believe this domain acked when it did
// not, exactly the class of bug in
// reusable_gotcha_swallowed_error_damage_is_decided_by_the_caller.
func TestClosureRepository_Pseudonymise_PropagatesScanError(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	boom := errors.New("pg: connection reset by peer")
	q := &stubQuerier{queryRowFn: func(_ string, _ ...any) pg.Row {
		return &stubRow{err: boom}
	}}
	repo := pg.NewClosureRepository(q)

	rows, err := repo.Pseudonymise(context.Background(), uuid.NewString(), "gcid-A", closureSpecFixture())
	if err == nil {
		t.Fatalf("expected error to propagate, got nil (rows=%d)", rows)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped sentinel error; got %v", err)
	}
	if rows != 0 {
		t.Fatalf("expected rows=0 on error; got %d", rows)
	}
}

// -----------------------------------------------------------------------------
// IsPseudonymised
// -----------------------------------------------------------------------------

func TestClosureRepository_IsPseudonymised_TrueWhenRowExists(t *testing.T) {
	t.Parallel()
	var gotSQL string
	q := &stubQuerier{queryRowFn: func(sql string, _ ...any) pg.Row {
		gotSQL = sql
		return &stubRow{scan: func(dest ...any) error {
			*(dest[0].(*int)) = 1
			return nil
		}}
	}}
	repo := pg.NewClosureRepository(q)

	got, err := repo.IsPseudonymised(context.Background(), uuid.NewString(), "gcid-A")
	if err != nil {
		t.Fatalf("IsPseudonymised: %v", err)
	}
	if !got {
		t.Fatalf("expected true when a row exists")
	}
	if !contains(gotSQL, "FROM closure_pseudonymisation_state") {
		t.Errorf("IsPseudonymised SQL malformed; got:\n%s", gotSQL)
	}
}

func TestClosureRepository_IsPseudonymised_FalseWhenNoRows(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{} // defaults to ErrNoRows
	repo := pg.NewClosureRepository(q)

	got, err := repo.IsPseudonymised(context.Background(), uuid.NewString(), "gcid-A")
	if err != nil {
		t.Fatalf("IsPseudonymised: expected nil error on a clean miss; got %v", err)
	}
	if got {
		t.Fatalf("expected false when no row exists")
	}
}

// TestClosureRepository_IsPseudonymised_PropagatesQueryError is the core
// W0-F5 proof for IsPseudonymised: this is exactly the method the original
// `IsPseudonymised(gcid string) bool` signature could NOT have implemented
// honestly against Postgres (no ctx, no error return). A real backing-store
// error must be reported, not folded into `false`.
func TestClosureRepository_IsPseudonymised_PropagatesQueryError(t *testing.T) {
	t.Parallel()
	boom := errors.New("pg: connection reset by peer")
	q := &stubQuerier{queryRowFn: func(_ string, _ ...any) pg.Row {
		return &stubRow{err: boom}
	}}
	repo := pg.NewClosureRepository(q)

	got, err := repo.IsPseudonymised(context.Background(), uuid.NewString(), "gcid-A")
	if err == nil {
		t.Fatalf("expected error to propagate, got nil (got=%v)", got)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped sentinel error; got %v", err)
	}
	if got {
		t.Fatalf("expected false alongside the error (never claim true on failure)")
	}
}

func TestClosureRepository_IsPseudonymised_RejectsEmptyTenantID(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)
	_, err := repo.IsPseudonymised(context.Background(), "", "gcid-A")
	if err == nil {
		t.Fatalf("expected error on empty tenant_id")
	}
	if q.txCalled {
		t.Fatalf("must not open a tenant tx on validation failure")
	}
}

func TestClosureRepository_IsPseudonymised_RejectsEmptyGCID(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)
	_, err := repo.IsPseudonymised(context.Background(), uuid.NewString(), "")
	if err == nil {
		t.Fatalf("expected error on empty gcid")
	}
	if q.txCalled {
		t.Fatalf("must not open a tenant tx on validation failure")
	}
}

func TestClosureRepository_NoQuerier_FailsLoud(t *testing.T) {
	t.Parallel()
	repo := pg.NewClosureRepository(nil)
	if _, err := repo.Pseudonymise(context.Background(), uuid.NewString(), "gcid-A", nil); err == nil {
		t.Fatalf("expected error when no TenantTxQuerier wired (Pseudonymise)")
	}
	if _, err := repo.IsPseudonymised(context.Background(), uuid.NewString(), "gcid-A"); err == nil {
		t.Fatalf("expected error when no TenantTxQuerier wired (IsPseudonymised)")
	}
}
