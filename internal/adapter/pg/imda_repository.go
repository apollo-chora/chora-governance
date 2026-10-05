// imda_repository.go — pgx-backed implementation of imda.Repository.
//
// Schema: imda_assessments (migration 0001_initial.sql + 0002_imda_canonical_labels.sql).
// The imda_dimension ENUM at the DB level holds the canonical ADR-141 labels
// post-0002, so no string conversion is needed between Go domain and DB.
//
// imda_assessments is APPEND-ONLY (trigger trg_imda_assess_no_update); this
// adapter never issues UPDATE or DELETE. Dashboard reads the latest row per
// dimension via DISTINCT ON.
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

// IMDARepository is the pgx-backed implementation of imda.Repository.
//
// q is a TenantTxQuerier (not the bare Querier): imda_assessments is
// RLS-protected by the `tenant_isolation` policy (migration 0001 lines
// 155-157) keyed on `current_setting('chora.tenant_id', true)::uuid`. Every
// read/write therefore runs inside WithTenantTx, which issues
// `SET LOCAL chora.tenant_id` BEFORE the statement — otherwise Postgres
// evaluates the policy's `”::uuid` cast against the unset GUC and raises
// 22P02 ("invalid input syntax for type uuid: \"\"") at row-evaluation time.
// That was the /o/dashboard OFFLINE defect: the dashboard read failed on any
// tenant with rows, while the empty-table unit test passed because the RLS
// qual is never evaluated with zero rows. Mirrors EvidenceRepository.
type IMDARepository struct {
	q TenantTxQuerier
}

// NewIMDARepository constructs an IMDARepository backed by the supplied
// TenantTxQuerier (typically *PgxPoolQuerier).
func NewIMDARepository(q TenantTxQuerier) *IMDARepository {
	return &IMDARepository{q: q}
}

// Append inserts a new Assessment row. Returns audit-style errors when the
// underlying DB raises a unique-violation (duplicate assessment_id).
func (r *IMDARepository) Append(ctx context.Context, a *imda.Assessment) error {
	if a == nil {
		return errors.New("imda.Append: nil assessment")
	}
	const q = `INSERT INTO imda_assessments (
		assessment_id, tenant_id, dimension, score, indicators, notes,
		assessed_by_gcid, assessed_at, created_at
	) VALUES (
		$1::uuid, $2::uuid, $3::imda_dimension, $4, $5, $6,
		$7::uuid, $8, $9
	)`
	// The RLS WITH CHECK on imda_assessments compares the inserted tenant_id
	// against the chora.tenant_id GUC — set it (and bind the same normalised
	// value to $2) so they agree.
	tenant := NormalizeTenantForRLS(a.TenantID)
	err := r.q.WithTenantTx(ctx, tenant, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			a.AssessmentID, tenant, string(a.Dimension), a.Score, a.Indicators, "",
			a.AssessorGcid, a.AssessedAt, a.AssessedAt,
		)
	})
	if err != nil {
		return fmt.Errorf("imda.Append: %w", err)
	}
	return nil
}

// Dashboard returns the most-recent assessment per dimension for a tenant.
// Always returns 4 entries (one per AllDimensions()); missing dimensions are
// returned as placeholder Assessments with Score=0 and AssessmentID="".
func (r *IMDARepository) Dashboard(ctx context.Context, tenantID string) ([]*imda.Assessment, error) {
	// DISTINCT ON (dimension) ORDER BY (dimension, assessed_at DESC) returns
	// the latest row per dimension. Postgres-native pattern; no GROUP BY hack.
	const q = `SELECT DISTINCT ON (dimension)
		assessment_id::TEXT, tenant_id::TEXT, dimension::TEXT, score,
		indicators, assessed_by_gcid::TEXT, assessed_at
		FROM imda_assessments
		WHERE tenant_id = $1::uuid
		ORDER BY dimension, assessed_at DESC, assessment_id DESC`
	// imda_assessments is RLS-protected on the chora.tenant_id GUC, so the read
	// runs inside WithTenantTx (SET LOCAL chora.tenant_id). Without the GUC the
	// policy's `''::uuid` cast raises 22P02 at iteration time on any tenant that
	// has rows. Bind the same normalised tenant to $1 so the WHERE predicate
	// agrees with the GUC.
	tenant := NormalizeTenantForRLS(tenantID)
	found := make(map[imda.Dimension]*imda.Assessment, 4)
	err := r.q.WithTenantTx(ctx, tenant, func(ctx context.Context, tx TenantScopedQuerier) error {
		rows, err := tx.Query(ctx, q, tenant)
		if err != nil {
			return fmt.Errorf("imda.Dashboard: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				a          imda.Assessment
				dim        string
				score      int
				assessedAt time.Time
				indicators []string
			)
			if err := rows.Scan(
				&a.AssessmentID, &a.TenantID, &dim, &score,
				&indicators, &a.AssessorGcid, &assessedAt,
			); err != nil {
				return fmt.Errorf("imda.Dashboard: scan: %w", err)
			}
			a.Dimension = imda.Canonicalise(dim)
			a.Score = score
			a.Indicators = indicators
			a.AssessedAt = assessedAt
			found[a.Dimension] = &a
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("imda.Dashboard: iter: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]*imda.Assessment, 0, 4)
	for _, dim := range imda.AllDimensions() {
		if v, ok := found[dim]; ok {
			out = append(out, v)
			continue
		}
		// Placeholder for missing dimension.
		out = append(out, &imda.Assessment{
			TenantID:   tenantID,
			Dimension:  dim,
			Score:      0,
			Indicators: []string{},
		})
	}
	return out, nil
}

// Compile-time check.
var _ imda.Repository = (*IMDARepository)(nil)
