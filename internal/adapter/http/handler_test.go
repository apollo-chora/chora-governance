// Package httpadapter_test exercises the HTTP adapter for chora-governance.
package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-governance/internal/adapter/http"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	gcidA   = "01970000-0000-7000-9000-000000000001"
)

func newServer() http.Handler {
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	ev := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	return httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo: policyRepo,
		AuditRepo:  auditRepo,
		IMDARepo:   imdaRepo,
		Evaluator:  ev,
	})
}

func authedReq(method, path string, body any) *http.Request {
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	r := httptest.NewRequest(method, path, buf)
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("gcid", gcidA)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// -----------------------------------------------------------------------------
// Health
// -----------------------------------------------------------------------------

func TestHealthz_ReturnsOK(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("body missing status:ok: %s", w.Body.String())
	}
}

func TestReadyz(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /api/policies — create + get + list
// -----------------------------------------------------------------------------

func TestCreatePolicy_201(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	body := map[string]any{
		"name":             "no-deletes",
		"enforcement_mode": "deny",
		"conditions": []map[string]any{
			{"field": "action", "op": "equals", "value": "atom.delete"},
		},
	}
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/policies", body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["rule_id"] == nil {
		t.Errorf("rule_id missing in response: %v", got)
	}
}

func TestCreatePolicy_RejectsMissingTenant(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/policies",
		bytes.NewBufferString(`{"name":"x","enforcement_mode":"deny","conditions":[{"field":"a","op":"equals","value":"b"}]}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("gcid", gcidA)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestGetPolicy_404OnUnknown(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/policies/unknown-id", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

func TestGetPolicy_RoundtripsCreated(t *testing.T) {
	t.Parallel()
	srv := newServer()

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/policies", map[string]any{
		"name":             "x",
		"enforcement_mode": "allow",
		"conditions":       []map[string]any{{"field": "a", "op": "equals", "value": "b"}},
	}))
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id := created["rule_id"].(string)

	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodGet, "/api/policies/"+id, nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("status = %d", w2.Code)
	}
}

func TestListPolicies(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/policies", map[string]any{
		"name": "x", "enforcement_mode": "allow",
		"conditions": []map[string]any{{"field": "a", "op": "equals", "value": "b"}},
	}))
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodGet, "/api/policies", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("status = %d", w2.Code)
	}
	var resp struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp.Total < 1 {
		t.Errorf("expected at least 1 policy; got %d", resp.Total)
	}
}

// -----------------------------------------------------------------------------
// /api/gatekeeper/evaluate
// -----------------------------------------------------------------------------

func TestEvaluate_ReturnsDecisionAndAudits(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/gatekeeper/evaluate", map[string]any{
		"action":   "atom.create",
		"resource": "learningatom",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Decision     string           `json:"decision"`
		MatchedRules []map[string]any `json:"matched_rules"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Decision != "permitted" {
		t.Errorf("Decision = %q; want permitted", got.Decision)
	}

	// Audit endpoint should now show the event
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, authedReq(http.MethodGet, "/api/audit?tenant_id="+tenantA, nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("audit list status = %d", w2.Code)
	}
	var audResp struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &audResp)
	if audResp.Total < 1 {
		t.Errorf("expected 1 audit event after evaluate; got %d", audResp.Total)
	}
}

// -----------------------------------------------------------------------------
// /api/audit
// -----------------------------------------------------------------------------

func TestAudit_RejectsMissingTenant(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestAudit_AcceptsLimitParam(t *testing.T) {
	t.Parallel()
	srv := newServer()
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/gatekeeper/evaluate", map[string]any{
			"action": "x", "resource": "y",
		}))
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/audit?limit=2", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Total > 2 {
		t.Errorf("Total = %d; want ≤2 (limit honoured)", resp.Total)
	}
}

// -----------------------------------------------------------------------------
// /api/imda
// -----------------------------------------------------------------------------

func TestCreateIMDAAssessment_201(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	body := map[string]any{
		"dimension":  "risk_levels",
		"score":      85,
		"indicators": []string{"risk-register-current"},
	}
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/imda/assessments", body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestCreateIMDAAssessment_RejectsInvalidDimension(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/imda/assessments", map[string]any{
		"dimension": "nope", "score": 50,
	}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 for invalid dimension", w.Code)
	}
}

func TestCreateIMDAAssessment_RejectsScoreOverhundred(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/imda/assessments", map[string]any{
		"dimension": "risk_levels", "score": 150,
	}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 for score>100", w.Code)
	}
}

func TestIMDADashboard_ReturnsFour(t *testing.T) {
	t.Parallel()
	srv := newServer()
	// Per ADR-141 the canonical labels are accountability / transparency /
	// safety_and_robustness / fairness_and_human_oversight.
	for _, dim := range []string{"accountability", "transparency", "safety_and_robustness", "fairness_and_human_oversight"} {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/imda/assessments", map[string]any{
			"dimension": dim, "score": 60,
		}))
		if w.Code != http.StatusCreated {
			t.Fatalf("seed dimension %s: status %d", dim, w.Code)
		}
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/imda/dashboard?tenant_id="+tenantA, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Dimensions []map[string]any `json:"dimensions"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Dimensions) != 4 {
		t.Errorf("dashboard dimensions = %d; want 4", len(resp.Dimensions))
	}
}

// TestCreateIMDAAssessment_DeprecatedAlias_AcceptedAndCanonicalised verifies
// the ADR-141 §3 backwards-compat alias mode: a v1 deprecated label sent on
// the wire is accepted (201 Created) and persisted under the canonical label.
func TestCreateIMDAAssessment_DeprecatedAlias_AcceptedAndCanonicalised(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/imda/assessments", map[string]any{
		"dimension": "risk_levels", // deprecated v1 alias
		"score":     65,
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201 (alias mode per ADR-141)", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["dimension"] != "accountability" {
		t.Errorf("persisted dimension = %v; want canonical %q (ADR-141 normalisation on construction)",
			got["dimension"], "accountability")
	}
}

// -----------------------------------------------------------------------------
// /api/compliance/reports
// -----------------------------------------------------------------------------

func TestCreateComplianceReport_201(t *testing.T) {
	t.Parallel()
	srv := newServer()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodPost, "/api/compliance/reports", map[string]any{}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["report_id"] == nil {
		t.Errorf("report_id missing in response: %v", got)
	}
}
