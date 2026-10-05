// Package pg — pgx-backed implementations of chora-governance domain
// repository ports.
//
// audit_repository.go satisfies audit.Repository against the `audit_log`
// table (migration 0001_initial.sql). The schema enforces APPEND-ONLY at
// the trigger level — this adapter never issues UPDATE or DELETE.
//
// Per Tier 5 D18 + ddd-enforcement.md, every gatekeeper decision (allow
// OR deny) lands here as a tamper-evident hash-chained Event. PrevHash +
// EntryHash are computed at Append time using audit.ComputeHash.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

// AuditRepository is the pgx-backed implementation of audit.Repository.
//
// audit_log carries the `tenant_isolation FOR ALL USING (tenant_id =
// current_setting('chora.tenant_id', true)::uuid)` RLS policy (migration 0001).
// Every access therefore runs inside TenantTxQuerier.WithTenantTx, which issues
// `SET LOCAL chora.tenant_id` before the SQL — on the bare pool an INSERT is
// rejected 42501 ("new row violates row-level security policy") and a SELECT
// silently returns zero rows. Same idiom as evidence_repository /
// imda_repository.
type AuditRepository struct {
	q TenantTxQuerier
}

// NewAuditRepository constructs an AuditRepository backed by the supplied
// TenantTxQuerier (typically *PgxPoolQuerier).
func NewAuditRepository(q TenantTxQuerier) *AuditRepository {
	return &AuditRepository{q: q}
}

// Append inserts a new event into audit_log. Computes PrevHash + EntryHash
// from the per-tenant chain head BEFORE insert (so the row is durable with
// the correct hash).
//
// The chain-head SELECT and the INSERT run inside ONE WithTenantTx: the chain
// head is per-tenant, so the `SET LOCAL chora.tenant_id` GUC must cover both —
// a bare head lookup would return zero rows under RLS and mis-compute the
// PrevHash as genesis for a non-genesis event.
//
// Rejects duplicate event_id by surfacing the underlying unique-violation as
// audit.ErrAlreadyExists.
func (r *AuditRepository) Append(ctx context.Context, e *audit.Event) error {
	tenantID := NormalizeTenantForRLS(e.TenantID)
	return r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		// Look up the per-tenant chain head (latest EntryHash for this tenant_id
		// in insertion order). Empty when this is the first event for the tenant.
		const headQ = `SELECT entry_hash
			FROM audit_log
			WHERE tenant_id = $1::uuid
			ORDER BY created_at DESC, event_id DESC
			LIMIT 1`
		var prev string
		if err := tx.QueryRow(ctx, headQ, e.TenantID).Scan(&prev); err != nil {
			if !errors.Is(err, ErrNoRows) {
				return fmt.Errorf("audit.Append: head lookup: %w", err)
			}
			prev = ""
		}

		e.PrevHash = prev
		e.EntryHash = audit.ComputeHash(e, prev)

		const insertQ = `INSERT INTO audit_log (
			event_id, tenant_id, gcid, agid, action, resource, decision, reason,
			subject_type, subject_id, actor_gcid,
			before_state, after_state,
			traceparent, tracestate,
			prev_hash, entry_hash,
			occurred_at, created_at
		) VALUES (
			$1::uuid, $2::uuid, $3::uuid, NULLIF($4,'')::uuid, $5, $6, $7::audit_decision, $8,
			$9, $10, $11::uuid,
			NULLIF($12,'')::jsonb, NULLIF($13,'')::jsonb,
			NULLIF($14,''), NULLIF($15,''),
			$16, $17,
			$18, $19
		)`
		if err := tx.Exec(ctx, insertQ,
			e.EventID, e.TenantID, e.Gcid, e.Agid,
			e.Action, e.Resource, string(e.Decision), e.Reason,
			e.SubjectType, e.SubjectID, e.ActorGcid,
			e.Before, e.After,
			e.Traceparent, e.Tracestate,
			e.PrevHash, e.EntryHash,
			e.CreatedAt, e.CreatedAt,
		); err != nil {
			if isUniqueViolation(err) {
				return audit.ErrAlreadyExists
			}
			return fmt.Errorf("audit.Append: insert: %w", err)
		}
		return nil
	})
}

// Query returns events matching filter, in insertion order (created_at ASC,
// event_id ASC tiebreaker).
func (r *AuditRepository) Query(ctx context.Context, f audit.QueryFilter) ([]*audit.Event, error) {
	// Build the query incrementally — keep it simple to avoid a query-builder
	// dependency. Append-only schema means no soft-delete predicate needed.
	q := `SELECT event_id::TEXT, tenant_id::TEXT, gcid::TEXT,
		COALESCE(agid::TEXT,''), action, resource, decision::TEXT, reason,
		subject_type, subject_id, actor_gcid::TEXT,
		COALESCE(before_state::TEXT,''), COALESCE(after_state::TEXT,''),
		COALESCE(traceparent,''), COALESCE(tracestate,''),
		prev_hash, entry_hash, created_at
		FROM audit_log
		WHERE 1=1`
	args := []any{}
	idx := 0
	addArg := func(v any) string {
		idx++
		args = append(args, v)
		return fmt.Sprintf("$%d", idx)
	}
	if f.TenantID != "" {
		q += " AND tenant_id = " + addArg(f.TenantID) + "::uuid"
	}
	if f.SubjectID != "" {
		q += " AND subject_id = " + addArg(f.SubjectID)
	}
	if f.SubjectType != "" {
		q += " AND subject_type = " + addArg(f.SubjectType)
	}
	if f.Action != "" {
		q += " AND action = " + addArg(f.Action)
	}
	if f.From != nil {
		q += " AND created_at >= " + addArg(*f.From)
	}
	if f.To != nil {
		q += " AND created_at <= " + addArg(*f.To)
	}
	q += " ORDER BY created_at ASC, event_id ASC"
	if f.Limit > 0 {
		q += " LIMIT " + addArg(f.Limit)
	}
	if f.Offset > 0 {
		q += " OFFSET " + addArg(f.Offset)
	}

	// RLS: scope the read to f.TenantID via SET LOCAL chora.tenant_id. An empty
	// filter tenant maps to NilTenant (platform), mirroring evidence
	// rlsScopeFilter — never a GUC-less bare read (which returns 0 rows silently
	// under the tenant_isolation policy). The whole row iteration runs inside
	// the tx so Rows are consumed before it closes.
	tenantID := NormalizeTenantForRLS(f.TenantID)
	out := []*audit.Event{}
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("audit.Query: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				e         audit.Event
				decision  string
				createdAt time.Time
			)
			if err := rows.Scan(
				&e.EventID, &e.TenantID, &e.Gcid, &e.Agid,
				&e.Action, &e.Resource, &decision, &e.Reason,
				&e.SubjectType, &e.SubjectID, &e.ActorGcid,
				&e.Before, &e.After,
				&e.Traceparent, &e.Tracestate,
				&e.PrevHash, &e.EntryHash, &createdAt,
			); err != nil {
				return fmt.Errorf("audit.Query: scan: %w", err)
			}
			e.Decision = audit.Decision(decision)
			e.CreatedAt = createdAt
			// prev_hash / entry_hash are CHAR(64): an empty genesis prev_hash
			// is space-padded by Postgres. Trim so VerifyChain compares the
			// logical value, not the padded column.
			e.PrevHash = strings.TrimSpace(e.PrevHash)
			e.EntryHash = strings.TrimSpace(e.EntryHash)
			out = append(out, &e)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("audit.Query: iter: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetByID looks up a single event by event_id. Returns audit.ErrNotFound when
// the row is absent.
//
// RLS: audit_log is tenant-scoped and GetByID carries no tenant, so the read
// runs under the NilTenant (platform) scope — it resolves platform-scoped rows
// only. The live tenant-scoped verification path is VerifyChain (which threads
// the tenant via Query); VerifyEntry — GetByID's sole caller — is not wired to
// a live route.
func (r *AuditRepository) GetByID(ctx context.Context, eventID string) (*audit.Event, error) {
	const q = `SELECT event_id::TEXT, tenant_id::TEXT, gcid::TEXT,
		COALESCE(agid::TEXT,''), action, resource, decision::TEXT, reason,
		subject_type, subject_id, actor_gcid::TEXT,
		COALESCE(before_state::TEXT,''), COALESCE(after_state::TEXT,''),
		COALESCE(traceparent,''), COALESCE(tracestate,''),
		prev_hash, entry_hash, created_at
		FROM audit_log
		WHERE event_id = $1::uuid`
	var out *audit.Event
	err := r.q.WithTenantTx(ctx, NilTenantUUID, func(ctx context.Context, tx TenantScopedQuerier) error {
		var (
			e         audit.Event
			decision  string
			createdAt time.Time
		)
		if err := tx.QueryRow(ctx, q, eventID).Scan(
			&e.EventID, &e.TenantID, &e.Gcid, &e.Agid,
			&e.Action, &e.Resource, &decision, &e.Reason,
			&e.SubjectType, &e.SubjectID, &e.ActorGcid,
			&e.Before, &e.After,
			&e.Traceparent, &e.Tracestate,
			&e.PrevHash, &e.EntryHash, &createdAt,
		); err != nil {
			if errors.Is(err, ErrNoRows) {
				return audit.ErrNotFound
			}
			return fmt.Errorf("audit.GetByID: %w", err)
		}
		e.Decision = audit.Decision(decision)
		e.CreatedAt = createdAt
		e.PrevHash = strings.TrimSpace(e.PrevHash)
		e.EntryHash = strings.TrimSpace(e.EntryHash)
		out = &e
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyEntry returns true if the stored EntryHash matches a recompute against
// PrevHash + canonical(event). False when tampered. ErrNotFound on miss.
func (r *AuditRepository) VerifyEntry(ctx context.Context, eventID string) (bool, error) {
	e, err := r.GetByID(ctx, eventID)
	if err != nil {
		return false, err
	}
	return audit.ComputeHash(e, e.PrevHash) == e.EntryHash, nil
}

// VerifyChain walks the per-tenant chain in insertion order and verifies each
// EntryHash + PrevHash linkage. Returns the first broken event_id + its index
// when the chain is tampered.
func (r *AuditRepository) VerifyChain(ctx context.Context, tenantID string) (audit.VerifyResult, error) {
	events, err := r.Query(ctx, audit.QueryFilter{TenantID: tenantID})
	if err != nil {
		return audit.VerifyResult{}, err
	}
	prev := ""
	for i, e := range events {
		if e.PrevHash != prev {
			return audit.VerifyResult{
				Valid:              false,
				Verified:           i,
				FirstBrokenEventID: e.EventID,
				BrokenAtIndex:      i,
			}, nil
		}
		if audit.ComputeHash(e, prev) != e.EntryHash {
			return audit.VerifyResult{
				Valid:              false,
				Verified:           i,
				FirstBrokenEventID: e.EventID,
				BrokenAtIndex:      i,
			}, nil
		}
		prev = e.EntryHash
	}
	return audit.VerifyResult{Valid: true, Verified: len(events)}, nil
}

// isUniqueViolation detects Postgres unique-constraint violations without a
// hard pgx/pq import. Mirrors the helper in adapter/outbox/store.go.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "23505") || contains(msg, "duplicate key value violates unique constraint")
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Compile-time check.
var _ audit.Repository = (*AuditRepository)(nil)
