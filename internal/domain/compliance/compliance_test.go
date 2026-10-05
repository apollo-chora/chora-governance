// Package compliance_test — derived ComplianceReport view aggregating recent
// AuditEvents + IMDADimensionAssessments.
package compliance_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/compliance"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

const (
	tenantA      = "01970000-0000-7000-8000-000000000001"
	assessorGcid = "01970000-0000-7000-9000-000000000001"
)

func TestGenerate_AssignsUUIDv7ReportID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	gen := compliance.NewGenerator(auditRepo, imdaRepo)

	r, err := gen.Generate(ctx, tenantA)
	if err != nil {
		t.Fatalf("Generate unexpected: %v", err)
	}
	if len(r.ReportID) != 36 {
		t.Errorf("ReportID length = %d; want 36", len(r.ReportID))
	}
	if r.ReportID[14] != '7' {
		t.Errorf("ReportID version char = %q; want '7'", string(r.ReportID[14]))
	}
}

func TestGenerate_IncludesAuditEventsForTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	gen := compliance.NewGenerator(auditRepo, imdaRepo)

	e, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: assessorGcid,
		Action: "atom.publish", Resource: "x", Decision: audit.DecisionDenied,
	})
	_ = auditRepo.Append(ctx, e)

	r, err := gen.Generate(ctx, tenantA)
	if err != nil {
		t.Fatalf("Generate unexpected: %v", err)
	}
	if r.AuditEventCount != 1 {
		t.Errorf("AuditEventCount = %d; want 1", r.AuditEventCount)
	}
	if r.AuditDeniedCount != 1 {
		t.Errorf("AuditDeniedCount = %d; want 1", r.AuditDeniedCount)
	}
}

func TestGenerate_IncludesIMDAScoresForFourDimensions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	gen := compliance.NewGenerator(auditRepo, imdaRepo)

	for _, d := range imda.AllDimensions() {
		a, _ := imda.New(imda.NewParams{
			TenantID: tenantA, Dimension: d, Score: 70, AssessorGcid: assessorGcid,
		})
		_ = imdaRepo.Append(ctx, a)
	}
	r, err := gen.Generate(ctx, tenantA)
	if err != nil {
		t.Fatalf("Generate unexpected: %v", err)
	}
	if len(r.IMDADashboard) != 4 {
		t.Errorf("IMDADashboard size = %d; want 4", len(r.IMDADashboard))
	}
}

func TestGenerate_TenantIsolation(t *testing.T) {
	t.Parallel()
	tenantB := "01970000-0000-7000-8000-000000000002"
	ctx := context.Background()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	gen := compliance.NewGenerator(auditRepo, imdaRepo)

	eA, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: assessorGcid,
		Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
	})
	_ = auditRepo.Append(ctx, eA)

	r, _ := gen.Generate(ctx, tenantB)
	if r.AuditEventCount != 0 {
		t.Errorf("tenantB report saw tenantA events: AuditEventCount = %d; want 0", r.AuditEventCount)
	}
}

func TestGenerate_RejectsEmptyTenant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	gen := compliance.NewGenerator(auditRepo, imdaRepo)
	_, err := gen.Generate(ctx, "")
	if err == nil {
		t.Errorf("expected error for empty tenant; got nil")
	}
}

// stubAuditRepo lets us inject a Query error to cover the error branch.
type stubAuditRepo struct{ err error }

func (s *stubAuditRepo) Append(_ context.Context, _ *audit.Event) error { return nil }
func (s *stubAuditRepo) Query(_ context.Context, _ audit.QueryFilter) ([]*audit.Event, error) {
	return nil, s.err
}
func (s *stubAuditRepo) GetByID(_ context.Context, _ string) (*audit.Event, error) {
	return nil, audit.ErrNotFound
}
func (s *stubAuditRepo) VerifyEntry(_ context.Context, _ string) (bool, error) {
	return false, audit.ErrNotFound
}
func (s *stubAuditRepo) VerifyChain(_ context.Context, _ string) (audit.VerifyResult, error) {
	return audit.VerifyResult{}, nil
}

// stubIMDARepo same.
type stubIMDARepo struct{ err error }

func (s *stubIMDARepo) Append(_ context.Context, _ *imda.Assessment) error { return nil }
func (s *stubIMDARepo) Dashboard(_ context.Context, _ string) ([]*imda.Assessment, error) {
	return nil, s.err
}

func TestGenerate_PropagatesAuditQueryError(t *testing.T) {
	t.Parallel()
	gen := compliance.NewGenerator(&stubAuditRepo{err: context.Canceled}, imda.NewInMemoryRepository())
	_, err := gen.Generate(context.Background(), tenantA)
	if err == nil {
		t.Errorf("expected error from audit Query; got nil")
	}
}

func TestGenerate_PropagatesIMDADashboardError(t *testing.T) {
	t.Parallel()
	gen := compliance.NewGenerator(audit.NewInMemoryRepository(), &stubIMDARepo{err: context.Canceled})
	_, err := gen.Generate(context.Background(), tenantA)
	if err == nil {
		t.Errorf("expected error from imda Dashboard; got nil")
	}
}
