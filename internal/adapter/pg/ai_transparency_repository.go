// ai_transparency_repository.go — pgx-backed implementation of
// aitransparency.Repository (ADR-225 backbone, migration 0011).
//
// Two tables, two RLS postures:
//
//   - transparency_disclosure_version — PLATFORM config (no tenant_id, no RLS,
//     mirrors policy_rules). ActiveDisclosureVersion reads it on the bare pool.
//   - ai_transparency_acknowledgement — APPEND-ONLY evidence, RLS tenant_isolation
//     on chora.tenant_id. LatestAcknowledgement + AppendAcknowledgement run
//     inside WithTenantTx so the `SET LOCAL chora.tenant_id` GUC is applied
//     BEFORE the statement (same contract as evidence_repository.go).
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/aitransparency"
)

// AiTransparencyRepository implements aitransparency.Repository over pgx.
//
// q is a TenantTxQuerier because the acknowledgement table is RLS-protected;
// the disclosure-version table is platform config read on the bare Querier.
type AiTransparencyRepository struct {
	q TenantTxQuerier
}

// NewAiTransparencyRepository constructs the repository.
func NewAiTransparencyRepository(q TenantTxQuerier) *AiTransparencyRepository {
	return &AiTransparencyRepository{q: q}
}

// ActiveDisclosureVersion returns the single active platform disclosure version
// (config-as-data, no RLS), or ErrNoActiveDisclosure.
func (r *AiTransparencyRepository) ActiveDisclosureVersion(ctx context.Context) (*aitransparency.DisclosureVersion, error) {
	const query = `SELECT version, status::TEXT, requires_reacknowledgement,
		effective_from, scope, locales::TEXT, created_by, approved_by
		FROM transparency_disclosure_version
		WHERE status = 'active' AND scope = 'platform'
		ORDER BY effective_from DESC
		LIMIT 1`
	var (
		v             aitransparency.DisclosureVersion
		status        string
		localesJSON   string
		effectiveFrom time.Time
	)
	// Platform config table has no RLS — the bare pool read is correct here.
	if err := r.q.QueryRow(ctx, query).Scan(
		&v.Version, &status, &v.RequiresReacknowledgement,
		&effectiveFrom, &v.Scope, &localesJSON, &v.CreatedBy, &v.ApprovedBy,
	); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, aitransparency.ErrNoActiveDisclosure
		}
		return nil, fmt.Errorf("aitransparency.ActiveDisclosureVersion: %w", err)
	}
	v.Status = aitransparency.DisclosureStatus(status)
	v.EffectiveFrom = effectiveFrom
	locales, err := decodeLocales(localesJSON)
	if err != nil {
		return nil, fmt.Errorf("aitransparency.ActiveDisclosureVersion: locales: %w", err)
	}
	v.Locales = locales
	return &v, nil
}

// decodeLocales parses the locales JSONB (locale -> variant -> copy). Empty ->
// empty map (never panics).
func decodeLocales(s string) (map[string]map[aitransparency.Variant]aitransparency.DisclosureCopy, error) {
	out := map[string]map[aitransparency.Variant]aitransparency.DisclosureCopy{}
	if s == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// LatestAcknowledgement returns the most recent acknowledgement for gcid within
// the tenant RLS scope, or ErrNotFound.
func (r *AiTransparencyRepository) LatestAcknowledgement(ctx context.Context, gcid, tenantID string) (*aitransparency.Acknowledgement, error) {
	const query = `SELECT id::TEXT, tenant_id::TEXT, gcid::TEXT, disclosure_version,
		surface, scope, first_shown_at, acknowledged_at, locale, minor_mode, created_at
		FROM ai_transparency_acknowledgement
		WHERE gcid = $1::uuid
		ORDER BY acknowledged_at DESC
		LIMIT 1`
	tenantID = NormalizeTenantForRLS(tenantID)
	var (
		a              aitransparency.Acknowledgement
		surface, scope string
	)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.QueryRow(ctx, query, gcid).Scan(
			&a.ID, &a.TenantID, &a.GCID, &a.DisclosureVersion,
			&surface, &scope, &a.FirstShownAt, &a.AcknowledgedAt, &a.Locale, &a.MinorMode, &a.CreatedAt,
		)
	})
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, aitransparency.ErrNotFound
		}
		return nil, fmt.Errorf("aitransparency.LatestAcknowledgement: %w", err)
	}
	a.Surface = aitransparency.Surface(surface)
	a.Scope = aitransparency.Scope(scope)
	return &a, nil
}

// AppendAcknowledgement inserts an acknowledgement, idempotent on
// (tenant_id, gcid, disclosure_version) via ON CONFLICT DO NOTHING.
func (r *AiTransparencyRepository) AppendAcknowledgement(ctx context.Context, a *aitransparency.Acknowledgement) error {
	if a == nil {
		return errors.New("aitransparency.AppendAcknowledgement: nil")
	}
	const query = `INSERT INTO ai_transparency_acknowledgement (
		id, tenant_id, gcid, disclosure_version, surface, scope,
		first_shown_at, acknowledged_at, locale, minor_mode, created_at
	) VALUES (
		$1::uuid, $2::uuid, $3::uuid, $4, $5, $6,
		$7, $8, $9, $10, $11
	)
	ON CONFLICT (tenant_id, gcid, disclosure_version) DO NOTHING`
	tenantID := NormalizeTenantForRLS(a.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, query,
			a.ID, tenantID, a.GCID, a.DisclosureVersion, string(a.Surface), string(a.Scope),
			a.FirstShownAt, a.AcknowledgedAt, a.Locale, a.MinorMode, a.CreatedAt,
		)
	})
	if err != nil {
		return fmt.Errorf("aitransparency.AppendAcknowledgement: %w", err)
	}
	return nil
}

// Compile-time interface check.
var _ aitransparency.Repository = (*AiTransparencyRepository)(nil)
