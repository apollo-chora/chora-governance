// Package pg is the pgx-backed adapter for chora-governance repository
// ports defined in internal/domain.
//
// Architecture mirrors chora-identity / chora-notifications:
//
//   - Domain ports (Repository on ledger / decision / correlation) are
//     defined in internal/domain/{ledger,decision,correlation}.
//   - This package implements those ports against a *pgxpool.Pool.
//   - A small `Querier` interface decouples SQL from pgx so unit tests
//     stub the SQL surface without a live DB.
//
// Resilience-priority directive (`feedback_resilience_priority`):
//
//   - All tenant-scoped queries run inside a transaction with `SET LOCAL
//     chora.tenant_id` applied BEFORE the user query.
//   - Append-only invariants (token_usage_ledger, agent_decision_log) are
//     enforced both at the table-trigger level (migrations) and at the
//     repository level (only Append + List/SumCost are exposed).
//
// Cross-DB queries forbidden — chora-governance reads only
// chora_governance. Inter-domain side effects flow through the
// chora_governance outbox (migration 0005).
package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the minimal Exec + Query + QueryRow surface this package needs
// from pgx.
//
// NOTE: the bare Exec/Query/QueryRow run directly on the pool with NO tenant
// GUC. They are RLS-safe ONLY for tables whose policy does NOT key on
// `chora.tenant_id`: policy_rules (migration 0006) has no RLS policy, so its
// bare-pool access is fine.
//
// Any table whose policy keys on `current_setting('chora.tenant_id', true)::uuid`
// MUST go through TenantTxQuerier.WithTenantTx — without the `SET LOCAL
// chora.tenant_id` GUC, Postgres evaluates the policy's `”::uuid` cast against
// the unset GUC and raises 22P02 at row-evaluation time (it stays hidden only
// while the table holds no rows for the queried tenant — the empty-table mask).
// That set is: the 12 IMDA D1-D4 evidence tables (migration 0003 — see
// evidence_repository.go) and imda_assessments (migration 0001 — see
// imda_repository.go; this was the /o/dashboard OFFLINE 22P02, now routed
// through WithTenantTx).
//
// audit_log (migration 0001 lines 95-97) ALSO carries the GUC-keyed policy
// while audit_repository still uses the bare pool — the same latent class,
// to verify + route through WithTenantTx separately.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

// NilTenantUUID is the canonical sentinel for platform-level / non-tenant
// rows in the UUID-typed tenant_id columns. Mirrors the chora-observability
// convention.
//
// The event envelope carries the string sentinel "platform" (blessed by
// chora-common/rls.ValidateTenantID), but the IMDA evidence read-model
// columns are UUID NOT NULL with a `current_setting('chora.tenant_id',
// true)::uuid` RLS policy — `'platform'::uuid` fails the cast.
// NormalizeTenantForRLS bridges the two at the adapter boundary.
const NilTenantUUID = "00000000-0000-0000-0000-000000000000"

// NormalizeTenantForRLS maps the envelope "platform" sentinel (and the empty
// string) to NilTenantUUID so it satisfies the UUID column + the `::uuid` RLS
// cast. Real tenant UUIDs pass through unchanged.
func NormalizeTenantForRLS(tenantID string) string {
	switch tenantID {
	case "", "platform":
		return NilTenantUUID
	default:
		return tenantID
	}
}

// TenantScopedQuerier is the Exec/Query/QueryRow surface available INSIDE a
// WithTenantTx callback. The `SET LOCAL chora.tenant_id` GUC is already
// applied on the transaction, so reads + writes against RLS-protected tables
// pass the `current_setting('chora.tenant_id', true)::uuid` policy.
type TenantScopedQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

// TenantTxQuerier is the surface the IMDA evidence pg adapter consumes: the
// base Querier plus the `chora.tenant_id`-GUC transaction runner. PgxPoolQuerier
// satisfies it; the unit-test stub implements it too.
//
// Resilience-priority + multi-tenant-rls: every RLS-protected evidence-table
// access (accountability_evidence, model_card_registry, … — the 12 tables in
// migration 0003) MUST run inside WithTenantTx — the bare Exec/Query/QueryRow
// run on the pool with NO tenant GUC and are therefore RLS-blocked on those
// tables (INSERT → "new row violates row-level security policy"; SELECT →
// zero rows).
type TenantTxQuerier interface {
	Querier
	// WithTenantTx opens a transaction, applies `SET LOCAL chora.tenant_id`
	// (tenantID is normalised + validated by the caller — pass a UUID or
	// NilTenantUUID), invokes fn with the tx-scoped querier, and commits.
	// fn MUST fully consume any Rows before returning (the tx closes on
	// return). A non-nil fn error rolls the tx back.
	WithTenantTx(ctx context.Context, tenantID string, fn func(context.Context, TenantScopedQuerier) error) error
}

// validateTenantIDLiteral rejects values unsafe to interpolate into a
// `SET LOCAL` statement (SET LOCAL is not parameterisable). Allows only
// hex/UUID-shaped strings (alphanum + dash) — mirrors
// chora-common/rls.validateSafeIdentifier. The "platform" sentinel
// must be NormalizeTenantForRLS'd to NilTenantUUID before reaching here.
func validateTenantIDLiteral(id string) error {
	if id == "" {
		return errors.New("pg: empty tenant_id for SET LOCAL")
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-':
			continue
		default:
			return fmt.Errorf("pg: tenant_id %q contains forbidden character for SET LOCAL", id)
		}
	}
	return nil
}

// Row is the minimal Scan surface used by the repos.
type Row interface {
	Scan(dest ...any) error
}

// Rows is the minimal multi-row surface.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
	Err() error
}

// ErrNoRows is the package-local sentinel for not-found.
var ErrNoRows = errors.New("pg: no rows in result set")

// PgxPoolQuerier wraps a *pgxpool.Pool with the local Querier shape.
type PgxPoolQuerier struct {
	pool *pgxpool.Pool
}

// NewPgxPoolQuerier wraps a pgxpool.Pool.
func NewPgxPoolQuerier(pool *pgxpool.Pool) *PgxPoolQuerier {
	return &PgxPoolQuerier{pool: pool}
}

// Exec runs a non-returning SQL statement.
func (q *PgxPoolQuerier) Exec(ctx context.Context, sql string, args ...any) error {
	if _, err := q.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("pg.Exec: %w", err)
	}
	return nil
}

// QueryRow runs a single-row query.
func (q *PgxPoolQuerier) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return &pgxPoolRow{r: q.pool.QueryRow(ctx, sql, args...)}
}

// Query runs a multi-row query.
func (q *PgxPoolQuerier) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := q.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pg.Query: %w", err)
	}
	return &pgxPoolRows{r: rows}, nil
}

// Pool returns the underlying pool.
func (q *PgxPoolQuerier) Pool() *pgxpool.Pool {
	return q.pool
}

// WithTenantTx opens a transaction, applies `SET LOCAL chora.tenant_id` so
// RLS-protected reads + writes pass the tenant_isolation policy, runs fn, then
// commits. SET LOCAL (not SET) keeps the GUC transaction-scoped — safe under
// PgBouncer transaction-pooling (no cross-request leak). Mirrors the
// chora-observability adapter (whose godoc calls out the analogous
// "kept this table empty" bug).
func (q *PgxPoolQuerier) WithTenantTx(ctx context.Context, tenantID string, fn func(context.Context, TenantScopedQuerier) error) error {
	if err := validateTenantIDLiteral(tenantID); err != nil {
		return err
	}
	tx, err := q.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg.WithTenantTx: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	// tenantID is validated above (hex/UUID/dash only) — safe to inline.
	// SET LOCAL is parsed by Postgres, not the prepared-statement path.
	if _, err := tx.Exec(ctx, "SET LOCAL chora.tenant_id = '"+tenantID+"'"); err != nil {
		return fmt.Errorf("pg.WithTenantTx: SET LOCAL chora.tenant_id: %w", err)
	}
	if err := fn(ctx, &txQuerier{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pg.WithTenantTx: commit: %w", err)
	}
	committed = true
	return nil
}

// txQuerier adapts a pgx.Tx to TenantScopedQuerier so repository SQL runs on
// the transaction that carries the SET LOCAL chora.tenant_id GUC.
type txQuerier struct{ tx pgx.Tx }

func (t *txQuerier) Exec(ctx context.Context, sql string, args ...any) error {
	if _, err := t.tx.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("pg.tx.Exec: %w", err)
	}
	return nil
}

func (t *txQuerier) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return &pgxPoolRow{r: t.tx.QueryRow(ctx, sql, args...)}
}

func (t *txQuerier) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := t.tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pg.tx.Query: %w", err)
	}
	return &pgxPoolRows{r: rows}, nil
}

// Compile-time checks.
var (
	_ TenantTxQuerier     = (*PgxPoolQuerier)(nil)
	_ TenantScopedQuerier = (*txQuerier)(nil)
)

type pgxPoolRow struct{ r pgx.Row }

func (r *pgxPoolRow) Scan(dest ...any) error {
	err := r.r.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoRows
	}
	return err
}

type pgxPoolRows struct{ r pgx.Rows }

func (r *pgxPoolRows) Next() bool             { return r.r.Next() }
func (r *pgxPoolRows) Scan(dest ...any) error { return r.r.Scan(dest...) }
func (r *pgxPoolRows) Close()                 { r.r.Close() }
func (r *pgxPoolRows) Err() error             { return r.r.Err() }
