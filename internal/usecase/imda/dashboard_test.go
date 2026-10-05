// dashboard_test.go — unit tests for the IMDA dashboard usecase. Per
// [[tdd-blanket]] 85% coverage gate.
package imda_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	domainimda "github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
	usecaseimda "github.com/apollo-chora/chora-governance/internal/usecase/imda"
)

func newRubricConfig() rubric.Config {
	return rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {Items: []rubric.ConfigItem{
				{ID: "raci", Title: "RACI", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
				{ID: "incident", Title: "Incident", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPartial},
			}},
			"transparency": {Items: []rubric.ConfigItem{
				{ID: "disclosure", Title: "Disclosure", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusFail},
			}},
			"safety_and_robustness": {Items: []rubric.ConfigItem{
				{ID: "guardrails", Title: "Guardrails", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
			}},
			"fairness_and_human_oversight": {Items: []rubric.ConfigItem{
				{ID: "raci", Title: "RACI", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPartial},
			}},
		},
	}
}

func newService(t *testing.T) (*usecaseimda.Service, domainimda.Repository, *evidence.InMemoryRepository) {
	t.Helper()
	imdaRepo := domainimda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	r, err := rubric.NewResolver(newRubricConfig(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	svc, err := usecaseimda.NewService(imdaRepo, r)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, imdaRepo, evRepo
}

// -----------------------------------------------------------------------------
// NewService guards
// -----------------------------------------------------------------------------

func TestNewService_RejectsNilRepo(t *testing.T) {
	t.Parallel()
	evRepo := evidence.NewInMemoryRepository()
	r, err := rubric.NewResolver(newRubricConfig(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := usecaseimda.NewService(nil, r); err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestNewService_RejectsNilResolver(t *testing.T) {
	t.Parallel()
	imdaRepo := domainimda.NewInMemoryRepository()
	if _, err := usecaseimda.NewService(imdaRepo, nil); err == nil {
		t.Fatal("expected error for nil resolver")
	}
}

// -----------------------------------------------------------------------------
// GetIMDADashboard — rubric-derived path (no recorded assessment)
// -----------------------------------------------------------------------------

func TestGetIMDADashboard_NoAssessment_UsesRubricPassRate(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t)
	res, err := svc.GetIMDADashboard(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("GetIMDADashboard: %v", err)
	}
	if res.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q; want tenant-1", res.TenantID)
	}
	if len(res.Dimensions) != 4 {
		t.Fatalf("len(Dimensions) = %d; want 4 (ADR-141)", len(res.Dimensions))
	}
	// accountability: 1 PASS + 1 PARTIAL → (1 + 0.5) / 2 = 0.75 → 75%
	var acc *usecaseimda.DashboardItem
	for i := range res.Dimensions {
		if res.Dimensions[i].Dimension == domainimda.DimensionRiskLevels {
			acc = &res.Dimensions[i]
		}
	}
	if acc == nil {
		t.Fatal("accountability dimension not found")
	}
	if acc.Score != 75 {
		t.Errorf("accountability Score = %d; want 75", acc.Score)
	}
	if acc.Source != "rubric" {
		t.Errorf("accountability Source = %q; want rubric", acc.Source)
	}
	if len(acc.RubricItems) != 2 {
		t.Errorf("len(RubricItems) = %d; want 2", len(acc.RubricItems))
	}
}

func TestGetIMDADashboard_FailItems_ReturnsZeroScore(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t)
	res, err := svc.GetIMDADashboard(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("GetIMDADashboard: %v", err)
	}
	var trans *usecaseimda.DashboardItem
	for i := range res.Dimensions {
		if res.Dimensions[i].Dimension == domainimda.DimensionStakeholderInteraction {
			trans = &res.Dimensions[i]
		}
	}
	if trans == nil {
		t.Fatal("transparency dimension not found")
	}
	// transparency: 1 FAIL → 0% → score 0
	if trans.Score != 0 {
		t.Errorf("transparency Score = %d; want 0", trans.Score)
	}
}

func TestGetIMDADashboard_AllPassItems_ReturnsHundredScore(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t)
	res, err := svc.GetIMDADashboard(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("GetIMDADashboard: %v", err)
	}
	var safety *usecaseimda.DashboardItem
	for i := range res.Dimensions {
		if res.Dimensions[i].Dimension == domainimda.DimensionInternalGovernance {
			safety = &res.Dimensions[i]
		}
	}
	if safety == nil {
		t.Fatal("safety dimension not found")
	}
	// safety: 1 PASS → 100% → score 100
	if safety.Score != 100 {
		t.Errorf("safety Score = %d; want 100", safety.Score)
	}
}

// -----------------------------------------------------------------------------
// GetIMDADashboard — assessment override path
// -----------------------------------------------------------------------------

func TestGetIMDADashboard_AssessmentOverridesRubricScore(t *testing.T) {
	t.Parallel()
	svc, imdaRepo, _ := newService(t)
	a, err := domainimda.New(domainimda.NewParams{
		TenantID:     "tenant-1",
		Dimension:    domainimda.DimensionRiskLevels,
		Score:        42,
		Indicators:   []string{"manual-review-pending"},
		AssessorGcid: "auditor-1",
	})
	if err != nil {
		t.Fatalf("New assessment: %v", err)
	}
	if err := imdaRepo.Append(context.Background(), a); err != nil {
		t.Fatalf("Append: %v", err)
	}
	res, err := svc.GetIMDADashboard(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("GetIMDADashboard: %v", err)
	}
	var acc *usecaseimda.DashboardItem
	for i := range res.Dimensions {
		if res.Dimensions[i].Dimension == domainimda.DimensionRiskLevels {
			acc = &res.Dimensions[i]
		}
	}
	if acc == nil {
		t.Fatal("accountability dimension not found")
	}
	if acc.Score != 42 {
		t.Errorf("Score = %d; want 42 (assessment override)", acc.Score)
	}
	if acc.Source != "assessment" {
		t.Errorf("Source = %q; want assessment", acc.Source)
	}
	if acc.AssessmentID == "" {
		t.Error("AssessmentID should be non-empty for assessment-override path")
	}
	if len(acc.Indicators) != 1 || acc.Indicators[0] != "manual-review-pending" {
		t.Errorf("Indicators = %v; want [manual-review-pending]", acc.Indicators)
	}
	// RubricItems must still be populated (FE drilldown semantics).
	if len(acc.RubricItems) != 2 {
		t.Errorf("len(RubricItems) = %d; want 2 (always populated)", len(acc.RubricItems))
	}
}

// -----------------------------------------------------------------------------
// GetIMDADashboard — error paths
// -----------------------------------------------------------------------------

func TestGetIMDADashboard_EmptyTenantIDRejected(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t)
	if _, err := svc.GetIMDADashboard(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
}
