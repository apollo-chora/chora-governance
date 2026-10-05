// imda_repository_test.go — IMDA pgx adapter tests.
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

func newAssessment(t *testing.T) *imda.Assessment {
	t.Helper()
	return &imda.Assessment{
		AssessmentID: uuid.NewString(),
		TenantID:     uuid.NewString(),
		Dimension:    imda.DimensionRiskLevels,
		Score:        85,
		Indicators:   []string{"i1", "i2"},
		AssessedAt:   time.Now().UTC(),
		AssessorGcid: uuid.NewString(),
	}
}

func TestIMDARepository_Append_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewIMDARepository(&stubQuerier{})
	if err := repo.Append(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil assessment")
	}
}

func TestIMDARepository_Append_EmitsInsertSQL(t *testing.T) {
	t.Parallel()
	a := newAssessment(t)
	q := &stubQuerier{}
	repo := pg.NewIMDARepository(q)
	if err := repo.Append(context.Background(), a); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO imda_assessments") {
		t.Errorf("expected INSERT INTO imda_assessments; got %q", q.execSQL)
	}
	if q.execArgs[0] != a.AssessmentID {
		t.Errorf("arg[0] = %v; want AssessmentID %q", q.execArgs[0], a.AssessmentID)
	}
	// Dimension arg is the string form of the canonical Dimension.
	if q.execArgs[2] != string(a.Dimension) {
		t.Errorf("arg[2] = %v; want %q", q.execArgs[2], string(a.Dimension))
	}
}

func TestIMDARepository_Append_ExecErrorWraps(t *testing.T) {
	t.Parallel()
	a := newAssessment(t)
	q := &stubQuerier{execErr: errors.New("db down")}
	repo := pg.NewIMDARepository(q)
	if err := repo.Append(context.Background(), a); err == nil {
		t.Fatal("expected error from exec failure")
	}
}

func TestIMDARepository_Dashboard_EmptyTenant_ReturnsFourPlaceholders(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewIMDARepository(q)
	got, err := repo.Dashboard(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("Dashboard: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("len = %d; want 4 (one per AllDimensions)", len(got))
	}
	for i, a := range got {
		if a.AssessmentID != "" {
			t.Errorf("placeholder %d should have empty AssessmentID; got %q", i, a.AssessmentID)
		}
		if a.Score != 0 {
			t.Errorf("placeholder %d Score = %d; want 0", i, a.Score)
		}
	}
}

func TestIMDARepository_Dashboard_QueryErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewIMDARepository(q)
	_, err := repo.Dashboard(context.Background(), "t1")
	if err == nil {
		t.Fatal("expected error to surface")
	}
}

// imda_assessments carries an RLS policy keyed on
// `current_setting('chora.tenant_id', true)::uuid` (migration 0001 lines
// 155-157). The Dashboard read therefore MUST run inside WithTenantTx so the
// `SET LOCAL chora.tenant_id` GUC is set — otherwise Postgres evaluates the
// policy's `”::uuid` cast per candidate row and raises 22P02
// ("invalid input syntax for type uuid: \"\"") at iteration time. This is the
// /o/dashboard OFFLINE root cause (the empty-table unit test masked it because
// the RLS qual is never evaluated when there are zero rows).
func TestIMDARepository_Dashboard_RunsInsideTenantTx(t *testing.T) {
	t.Parallel()
	const tenant = "11111111-1111-1111-1111-111111111111"
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) { return &stubRows{}, nil },
	}
	repo := pg.NewIMDARepository(q)
	if _, err := repo.Dashboard(context.Background(), tenant); err != nil {
		t.Fatalf("Dashboard: %v", err)
	}
	if !q.txCalled {
		t.Fatal("Dashboard ran on the bare pool; expected WithTenantTx (SET LOCAL chora.tenant_id) so the imda_assessments RLS policy passes")
	}
	if q.txTenantID != tenant {
		t.Errorf("GUC tenant = %q; want the request tenant %q", q.txTenantID, tenant)
	}
}

// Append (RecordAssessment) writes a row whose tenant_id must satisfy the same
// RLS policy's WITH CHECK — so it too must run inside WithTenantTx, with the
// GUC set to the row's own tenant.
func TestIMDARepository_Append_RunsInsideTenantTx(t *testing.T) {
	t.Parallel()
	a := newAssessment(t)
	q := &stubQuerier{}
	repo := pg.NewIMDARepository(q)
	if err := repo.Append(context.Background(), a); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !q.txCalled {
		t.Fatal("Append ran on the bare pool; expected WithTenantTx so the imda_assessments RLS WITH CHECK passes")
	}
	if q.txTenantID != a.TenantID {
		t.Errorf("GUC tenant = %q; want row tenant %q", q.txTenantID, a.TenantID)
	}
}
