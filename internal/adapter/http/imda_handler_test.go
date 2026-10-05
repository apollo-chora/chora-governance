// Tests for the IMDA D1-D4 HTTP handlers + Three-Audience explanation API
// + evidence-pack export endpoint.
package httpadapter_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-governance/internal/adapter/http"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/evidencepack"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

func newIMDAServer(t *testing.T) (http.Handler, evidence.Repository, audit.Repository) {
	t.Helper()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	ev := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	proj := projector.New(evRepo)
	exp := evidencepack.New(evRepo, auditRepo)
	srv := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:   policyRepo,
		AuditRepo:    auditRepo,
		IMDARepo:     imdaRepo,
		Evaluator:    ev,
		EvidenceRepo: evRepo,
		Projector:    proj,
		Exporter:     exp,
	})
	return srv, evRepo, auditRepo
}

func authedAuditorReq(method, path string, body any) *http.Request {
	r := authedReq(method, path, body)
	r.Header.Set("X-Chora-Role", "auditor")
	return r
}

func authedLearnerReq(method, path string, body any) *http.Request {
	r := authedReq(method, path, body)
	r.Header.Set("X-Chora-Role", "learner")
	return r
}

// -----------------------------------------------------------------------------
// /v1/governance/dimensions/d1/accountability
// -----------------------------------------------------------------------------

func TestD1Accountability_AuditorAccess(t *testing.T) {
	t.Parallel()
	srv, evRepo, _ := newIMDAServer(t)
	ev, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID: "ev-d1-1", TenantID: tenantA,
		AgentID: "agent-1", OwnerGcid: "owner-1",
		DecisionID: "dec-1", DecisionType: "x",
	})
	_ = evRepo.AppendAccountability(context.Background(), ev)

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/dimensions/d1/accountability", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["total"].(float64) != 1 {
		t.Errorf("total=%v want 1 (body=%s)", body["total"], w.Body.String())
	}
}

func TestD1Accountability_LearnerForbidden(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedLearnerReq(http.MethodGet, "/v1/governance/dimensions/d1/accountability", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403", w.Code)
	}
}

func TestD1Accountability_RejectsNonGet(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodPost, "/v1/governance/dimensions/d1/accountability", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/governance/dimensions/d2/transparency
// -----------------------------------------------------------------------------

func TestD2Transparency_LearnerCanView(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedLearnerReq(http.MethodGet, "/v1/governance/dimensions/d2/transparency", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status=%d want 200", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/governance/dimensions/d3/safety
// -----------------------------------------------------------------------------

func TestD3Safety_AuditorAccess(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/dimensions/d3/safety", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestD3Safety_LearnerForbidden(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedLearnerReq(http.MethodGet, "/v1/governance/dimensions/d3/safety", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/governance/dimensions/d4/fairness — auditor-only
// -----------------------------------------------------------------------------

func TestD4Fairness_AuditorOnly(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/dimensions/d4/fairness", nil))
	if w.Code != http.StatusOK {
		t.Errorf("auditor status=%d want 200", w.Code)
	}

	w = httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/v1/governance/dimensions/d4/fairness", nil)) // no role header
	if w.Code != http.StatusForbidden {
		t.Errorf("no-role status=%d want 403", w.Code)
	}

	w = httptest.NewRecorder()
	srv.ServeHTTP(w, func() *http.Request {
		r := authedReq(http.MethodGet, "/v1/governance/dimensions/d4/fairness", nil)
		r.Header.Set("X-Chora-Role", "instructor_admin")
		return r
	}())
	if w.Code != http.StatusForbidden {
		t.Errorf("instructor_admin status=%d want 403 (D4 is auditor-only)", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/governance/decisions/{id}/explanation — Three-Audience
// -----------------------------------------------------------------------------

func TestDecisionExplanation_LearnerSeesOnlyLearner(t *testing.T) {
	t.Parallel()
	srv, evRepo, _ := newIMDAServer(t)
	for i, aud := range []evidence.Audience{
		evidence.AudienceLearner,
		evidence.AudienceInstructorAdmin,
		evidence.AudienceAuditor,
	} {
		ev, _ := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
			EventID:  "ev-" + string(rune('a'+i)),
			TenantID: tenantA, DecisionID: "dec-1",
			Audience: aud, ExplanationMD: "x",
		})
		_ = evRepo.AppendDecisionExplanation(context.Background(), ev)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedLearnerReq(http.MethodGet, "/v1/governance/decisions/dec-1/explanation", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["total"].(float64) != 1 {
		t.Errorf("learner total=%v want 1 (body=%s)", body["total"], w.Body.String())
	}
}

func TestDecisionExplanation_AuditorSeesAll(t *testing.T) {
	t.Parallel()
	srv, evRepo, _ := newIMDAServer(t)
	for i, aud := range []evidence.Audience{
		evidence.AudienceLearner,
		evidence.AudienceInstructorAdmin,
		evidence.AudienceAuditor,
	} {
		ev, _ := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
			EventID:  "ev-" + string(rune('a'+i)),
			TenantID: tenantA, DecisionID: "dec-1",
			Audience: aud, ExplanationMD: "x",
		})
		_ = evRepo.AppendDecisionExplanation(context.Background(), ev)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/decisions/dec-1/explanation", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["total"].(float64) != 3 {
		t.Errorf("auditor total=%v want 3", body["total"])
	}
}

func TestDecisionExplanation_LearnerCannotRequestAuditorView(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	r := authedLearnerReq(http.MethodGet, "/v1/governance/decisions/dec-1/explanation?audience=auditor", nil)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403", w.Code)
	}
}

func TestDecisionExplanation_InvalidAudience(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	r := authedAuditorReq(http.MethodGet, "/v1/governance/decisions/dec-1/explanation?audience=regulator", nil)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400", w.Code)
	}
}

func TestDecisionExplanation_BadPath(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/decisions/dec-1/wrong", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/governance/audit/verify
// -----------------------------------------------------------------------------

func TestAuditVerify_AuditorEmptyChainValid(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/audit/verify", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["valid"].(bool) != true {
		t.Errorf("valid=%v want true", body["valid"])
	}
}

func TestAuditVerify_LearnerForbidden(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedLearnerReq(http.MethodGet, "/v1/governance/audit/verify", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403", w.Code)
	}
}

func TestAuditVerify_DetectsTampering(t *testing.T) {
	t.Parallel()
	srv, _, ar := newIMDAServer(t)
	ae, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA, Action: "policy.update",
		Decision: audit.DecisionPermitted, Reason: "test",
	})
	_ = ar.Append(context.Background(), ae)

	// Tamper.
	if im, ok := ar.(*audit.InMemoryRepository); ok {
		im.TamperEntryHash(ae.EventID, "deadbeef")
	}

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/audit/verify", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["valid"].(bool) != false {
		t.Errorf("valid=%v want false (tampered)", body["valid"])
	}
}

// -----------------------------------------------------------------------------
// /v1/governance/evidence/export — REAL ZIP
// -----------------------------------------------------------------------------

func TestEvidenceExport_AuditorReturnsZIP(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodPost, "/v1/governance/evidence/export", map[string]any{
		"dimensions": []string{"D1", "D2"},
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("content-type=%q want application/zip", ct)
	}
	if pid := w.Header().Get("X-Pack-ID"); pid == "" {
		t.Error("X-Pack-ID header missing")
	}
	if msha := w.Header().Get("X-Manifest-SHA256"); len(msha) != 64 {
		t.Errorf("X-Manifest-SHA256 len=%d want 64", len(msha))
	}
	// Verify it's actually a ZIP
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("not a valid ZIP: %v", err)
	}
	hasManifest := false
	for _, f := range zr.File {
		if f.Name == "manifest.yaml" {
			hasManifest = true
			rc, _ := f.Open()
			body, _ := io.ReadAll(rc)
			rc.Close()
			if !bytes.Contains(body, []byte("tenant_id: "+tenantA)) {
				t.Errorf("manifest missing tenant_id")
			}
		}
	}
	if !hasManifest {
		t.Error("ZIP missing manifest.yaml")
	}
}

func TestEvidenceExport_LearnerForbidden(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedLearnerReq(http.MethodPost, "/v1/governance/evidence/export", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403", w.Code)
	}
}

func TestEvidenceExport_RejectsBadFromTimestamp(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodPost, "/v1/governance/evidence/export", map[string]any{
		"from": "not-a-timestamp",
	}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /v1/governance/evidence/project (synchronous projector entry)
// -----------------------------------------------------------------------------

func TestEvidenceProject_HappyPath(t *testing.T) {
	t.Parallel()
	srv, evRepo, _ := newIMDAServer(t)
	body := map[string]any{
		"event_id":       "01970000-0000-7000-a000-000000000001",
		"tenant_id":      tenantA,
		"imda_dimension": "accountability",
		"event_type":     "chora.closure.account_closed.v1",
		"agent_id":       "agent-closure",
		"owner_gcid":     "owner-1",
		"decision_id":    "dec-1",
		"decision_type":  "close_account",
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodPost, "/v1/governance/evidence/project", body))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	rows, _ := evRepo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: tenantA})
	if len(rows) != 1 {
		t.Errorf("accountability rows=%d want 1", len(rows))
	}
}

func TestEvidenceProject_RequiresEventID(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	body := map[string]any{
		"tenant_id":      tenantA,
		"imda_dimension": "accountability",
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodPost, "/v1/governance/evidence/project", body))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400", w.Code)
	}
}

func TestEvidenceProject_LearnerForbidden(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedLearnerReq(http.MethodPost, "/v1/governance/evidence/project", map[string]any{}))
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403", w.Code)
	}
}

func TestEvidenceProject_RejectsGet(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/evidence/project", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", w.Code)
	}
}

func TestEvidenceProject_InvalidProjectionFails(t *testing.T) {
	t.Parallel()
	srv, _, _ := newIMDAServer(t)
	body := map[string]any{
		"event_id":       "ev1",
		"tenant_id":      tenantA,
		"imda_dimension": "accountability",
		"event_type":     "chora.x.v1",
		// missing agent_id, owner_gcid, decision_id, decision_type
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodPost, "/v1/governance/evidence/project", body))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400", w.Code)
	}
}

// -----------------------------------------------------------------------------
// IMDA routes are NOT wired when EvidenceRepo is absent (back-compat)
// -----------------------------------------------------------------------------

func TestIMDA_Routes_NotWiredWhenDepsAbsent(t *testing.T) {
	t.Parallel()
	srv := newServer() // builds without EvidenceRepo
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedAuditorReq(http.MethodGet, "/v1/governance/dimensions/d1/accountability", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404 (no IMDA wiring)", w.Code)
	}
}
