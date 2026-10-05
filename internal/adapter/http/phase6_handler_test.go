// Package httpadapter — Phase-6 BFF-facing handler tests.
//
// Tests the new GET /governance/{tenant_id} endpoint added so the
// chora-gateway HTTPUpstream.GetGovernance method has a concrete
// downstream target. Returns the IMDA Dashboard JSON shape.
package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

// phase6FakeIMDARepo is a minimal stub matching imda.Repository for
// Phase-6 tests.
type phase6FakeIMDARepo struct {
	assessments []*imda.Assessment
}

func (f *phase6FakeIMDARepo) Append(_ context.Context, a *imda.Assessment) error {
	f.assessments = append(f.assessments, a)
	return nil
}

func (f *phase6FakeIMDARepo) Dashboard(_ context.Context, _ string) ([]*imda.Assessment, error) {
	return f.assessments, nil
}

func TestPhase6_GovernanceByTenantID_Returns200(t *testing.T) {
	repo := &phase6FakeIMDARepo{
		assessments: []*imda.Assessment{
			{AssessmentID: "a-1", TenantID: "tenant-a", Dimension: imda.DimensionRiskLevels, Score: 88},
			{AssessmentID: "a-2", TenantID: "tenant-a", Dimension: imda.DimensionStakeholderInteraction, Score: 92},
		},
	}
	h := newPhase6GovernanceHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/governance/tenant-a", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if body["tenant_id"] != "tenant-a" {
		t.Errorf("tenant_id = %v; want tenant-a", body["tenant_id"])
	}
	dims, ok := body["dimensions"].([]any)
	if !ok {
		t.Fatalf("body.dimensions not an array: %v", body)
	}
	if len(dims) != 2 {
		t.Errorf("dimensions len = %d; want 2", len(dims))
	}
}

func TestPhase6_GovernanceByTenantID_RejectsMissingID(t *testing.T) {
	repo := &phase6FakeIMDARepo{}
	h := newPhase6GovernanceHandler(repo)

	req := httptest.NewRequest(http.MethodGet, "/governance/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("missing tenant_id: status = %d; want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestPhase6_GovernanceByTenantID_OnlyGET(t *testing.T) {
	repo := &phase6FakeIMDARepo{}
	h := newPhase6GovernanceHandler(repo)

	req := httptest.NewRequest(http.MethodPost, "/governance/tenant-a", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status = %d; want 405", w.Code)
	}
}
