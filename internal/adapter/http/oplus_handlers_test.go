// oplus_handlers_test.go — integration tests for /api/hitl/pending +
// /api/imda/dimensions/{name}/rubric. Table-driven per
// [[development-execution]] §TDD Enforcement; per [[feedback-no-local-cicd-run]]
// runs via Cloud Build.
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-governance/internal/adapter/http"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	domainimda "github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
	usecaseimda "github.com/apollo-chora/chora-governance/internal/usecase/imda"
)

// rubricConfigForTest mirrors a slice of config/imda_rubric.yaml — enough to
// drive the /api/imda/dimensions/{name}/rubric tests without loading the real
// YAML file from disk.
func rubricConfigForTest() rubric.Config {
	return rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {Items: []rubric.ConfigItem{
				{ID: "raci", Title: "RACI Matrix", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPartial},
				{ID: "incident", Title: "Incident Runbook", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
			}},
			"transparency": {Items: []rubric.ConfigItem{
				{ID: "disclosure", Title: "Disclosure", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusFail},
			}},
		},
	}
}

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := domainimda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	evaluator := gatekeeper.NewEvaluator(policyRepo, auditRepo)

	resolver, err := rubric.NewResolver(rubricConfigForTest(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	dashboardSvc, err := usecaseimda.NewService(imdaRepo, resolver)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	return httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:     policyRepo,
		AuditRepo:      auditRepo,
		IMDARepo:       imdaRepo,
		Evaluator:      evaluator,
		EvidenceRepo:   evRepo,
		RubricResolver: resolver,
		DashboardSvc:   dashboardSvc,
	})
}

// -----------------------------------------------------------------------------
// /api/hitl/pending
// -----------------------------------------------------------------------------

func TestHITLPending_RequiresGET(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/pending", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rr.Code)
	}
}

func TestHITLPending_RequiresTenant(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/hitl/pending", nil)
	// Note: X-Tenant-Id missing
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (X-Tenant-Id required)", rr.Code)
	}
}

func TestHITLPending_EmptyResultDefault(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/hitl/pending", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rr.Code)
	}
	var body struct {
		Items  []map[string]any `json:"items"`
		Total  int              `json:"total"`
		Limit  int              `json:"limit"`
		Offset int              `json:"offset"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 0 || len(body.Items) != 0 {
		t.Errorf("expected empty result; got total=%d items=%d", body.Total, len(body.Items))
	}
	if body.Limit != 20 {
		t.Errorf("limit = %d; want default 20", body.Limit)
	}
}

func TestHITLPending_StatusFilterApprove(t *testing.T) {
	t.Parallel()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := domainimda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	evaluator := gatekeeper.NewEvaluator(policyRepo, auditRepo)

	// Seed one approve + one reject HITL decision for tenant-1.
	approve, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID:       "ev-1",
		TenantID:      "tenant-1",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		OperatorGcid:  "op-1",
		Decision:      evidence.HitlApprove,
		AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewHITLDecision approve: %v", err)
	}
	if err := evRepo.AppendHITLDecision(context.Background(), approve); err != nil {
		t.Fatalf("AppendHITLDecision approve: %v", err)
	}
	reject, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID:       "ev-2",
		TenantID:      "tenant-1",
		DecisionID:    "dec-2",
		RunID:         "run-2",
		OperatorGcid:  "op-2",
		Decision:      evidence.HitlReject,
		AutonomyLevel: evidence.AutonomyHitlL2,
	})
	if err != nil {
		t.Fatalf("NewHITLDecision reject: %v", err)
	}
	if err := evRepo.AppendHITLDecision(context.Background(), reject); err != nil {
		t.Fatalf("AppendHITLDecision reject: %v", err)
	}

	resolver, err := rubric.NewResolver(rubricConfigForTest(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	dashboardSvc, err := usecaseimda.NewService(imdaRepo, resolver)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	router := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:     policyRepo,
		AuditRepo:      auditRepo,
		IMDARepo:       imdaRepo,
		Evaluator:      evaluator,
		EvidenceRepo:   evRepo,
		RubricResolver: resolver,
		DashboardSvc:   dashboardSvc,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/hitl/pending?status=approve", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rr.Code)
	}
	var body struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 1 {
		t.Errorf("Total = %d; want 1 (only approve matches)", body.Total)
	}
	if len(body.Items) > 0 {
		got := body.Items[0]["decision"]
		if got != "approve" {
			t.Errorf("items[0].decision = %v; want approve", got)
		}
	}
}

func TestHITLPending_PendingFilterReturnsEmpty(t *testing.T) {
	t.Parallel()
	// Seed only approve + reject — no pending. Pending filter returns 0.
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := domainimda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	evaluator := gatekeeper.NewEvaluator(policyRepo, auditRepo)

	approve, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "ev-1", TenantID: "tenant-1", DecisionID: "dec-1",
		RunID: "run-1", OperatorGcid: "op-1",
		Decision: evidence.HitlApprove, AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewHITLDecision: %v", err)
	}
	if err := evRepo.AppendHITLDecision(context.Background(), approve); err != nil {
		t.Fatalf("AppendHITLDecision: %v", err)
	}
	resolver, err := rubric.NewResolver(rubricConfigForTest(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	dashboardSvc, err := usecaseimda.NewService(imdaRepo, resolver)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	router := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:     policyRepo,
		AuditRepo:      auditRepo,
		IMDARepo:       imdaRepo,
		Evaluator:      evaluator,
		EvidenceRepo:   evRepo,
		RubricResolver: resolver,
		DashboardSvc:   dashboardSvc,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/hitl/pending", nil) // default status=pending
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rr.Code)
	}
	var body struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 0 {
		t.Errorf("Total = %d; want 0 (no pending rows)", body.Total)
	}
}

// TestHITLPending_ExposesAssigneeGcidNullByDefault verifies the response
// envelope carries the new `assignee_gcid` field and that it serialises as
// JSON `null` when the row is unassigned (the canonical default before any
// claim endpoint ships). Per the schema-reconciliation 0008 migration.
func TestHITLPending_ExposesAssigneeGcidNullByDefault(t *testing.T) {
	t.Parallel()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := domainimda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	evaluator := gatekeeper.NewEvaluator(policyRepo, auditRepo)

	approve, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "ev-1", TenantID: "tenant-1", DecisionID: "dec-1",
		RunID: "run-1", OperatorGcid: "op-1",
		Decision: evidence.HitlApprove, AutonomyLevel: evidence.AutonomyHitlL1,
		// AssigneeGcid omitted → nil (default unassigned).
	})
	if err != nil {
		t.Fatalf("NewHITLDecision: %v", err)
	}
	if err := evRepo.AppendHITLDecision(context.Background(), approve); err != nil {
		t.Fatalf("AppendHITLDecision: %v", err)
	}
	resolver, err := rubric.NewResolver(rubricConfigForTest(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	dashboardSvc, err := usecaseimda.NewService(imdaRepo, resolver)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	router := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:     policyRepo,
		AuditRepo:      auditRepo,
		IMDARepo:       imdaRepo,
		Evaluator:      evaluator,
		EvidenceRepo:   evRepo,
		RubricResolver: resolver,
		DashboardSvc:   dashboardSvc,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/hitl/pending?status=approve", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rr.Code)
	}
	// Parse as a generic map so we can assert JSON-null behaviour on the
	// nullable `assignee_gcid` field — `_, has := m["assignee_gcid"]` is
	// the canonical way to verify the key is emitted (even when null).
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) == 0 {
		t.Fatal("items empty; want 1")
	}
	first := body.Items[0]
	assignee, has := first["assignee_gcid"]
	if !has {
		t.Errorf("response missing 'assignee_gcid' key: %+v", first)
	}
	if assignee != nil {
		t.Errorf("assignee_gcid = %v; want null (unassigned default)", assignee)
	}
}

func TestHITLPending_PaginationClamps(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	// Empty repo — verify limit clamp via query.
	req := httptest.NewRequest(http.MethodGet, "/api/hitl/pending?limit=999&offset=0", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rr.Code)
	}
	var body struct {
		Limit int `json:"limit"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Limit != 100 {
		t.Errorf("Limit = %d; want 100 (capped from 999)", body.Limit)
	}
}

// -----------------------------------------------------------------------------
// /api/hitl/decisions/{id}/claim + /release (N7 self-claim endpoint)
// -----------------------------------------------------------------------------

func seedPendingHITLDecision(t *testing.T, evRepo *evidence.InMemoryRepository, tenantID, decisionID string) {
	t.Helper()
	d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "ev-" + decisionID, TenantID: tenantID,
		DecisionID: decisionID, RunID: "run-1", OperatorGcid: "op-bootstrap",
		Decision: evidence.HitlApprove, AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewHITLDecision: %v", err)
	}
	d.Decision = evidence.HitlVerdict("pending")
	d.OperatorGcid = ""
	d.AssigneeGcid = nil
	if err := evRepo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("AppendHITLDecision: %v", err)
	}
}

func newRouterWithSeededHITL(t *testing.T) (http.Handler, *evidence.InMemoryRepository) {
	t.Helper()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := domainimda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	evaluator := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	resolver, err := rubric.NewResolver(rubricConfigForTest(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	dashboardSvc, err := usecaseimda.NewService(imdaRepo, resolver)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	router := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:     policyRepo,
		AuditRepo:      auditRepo,
		IMDARepo:       imdaRepo,
		Evaluator:      evaluator,
		EvidenceRepo:   evRepo,
		RubricResolver: resolver,
		DashboardSvc:   dashboardSvc,
	})
	return router, evRepo
}

func TestHITLClaim_RequiresPOST(t *testing.T) {
	t.Parallel()
	router, _ := newRouterWithSeededHITL(t)
	req := httptest.NewRequest(http.MethodGet, "/api/hitl/decisions/dec-1/claim", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rr.Code)
	}
}

func TestHITLClaim_NotFoundReturns404(t *testing.T) {
	t.Parallel()
	router, _ := newRouterWithSeededHITL(t)
	body := bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/missing/claim", body)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHITLClaim_BlankGcidReturns422(t *testing.T) {
	t.Parallel()
	router, evRepo := newRouterWithSeededHITL(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")
	body := bytes.NewBufferString(`{"operator_gcid":"   "}`)
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/claim", body)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHITLClaim_MissingBodyReturns422(t *testing.T) {
	t.Parallel()
	router, evRepo := newRouterWithSeededHITL(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/claim", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHITLClaim_HappyPathReturns200(t *testing.T) {
	t.Parallel()
	router, evRepo := newRouterWithSeededHITL(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")
	body := bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/claim", body)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		DecisionID   string  `json:"decision_id"`
		AssigneeGcid *string `json:"assignee_gcid"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AssigneeGcid == nil || *resp.AssigneeGcid != "alice-gcid" {
		t.Errorf("assignee_gcid = %v; want alice-gcid", resp.AssigneeGcid)
	}
}

func TestHITLClaim_AlreadyClaimedReturns409(t *testing.T) {
	t.Parallel()
	router, evRepo := newRouterWithSeededHITL(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")

	body1 := bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/claim", body1)
	req1.Header.Set("X-Tenant-Id", "tenant-1")
	req1.Header.Set("gcid", "user-1")
	req1.Header.Set("Content-Type", "application/json")
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first claim: status = %d; want 200", rr1.Code)
	}

	body2 := bytes.NewBufferString(`{"operator_gcid":"bob-gcid"}`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/claim", body2)
	req2.Header.Set("X-Tenant-Id", "tenant-1")
	req2.Header.Set("gcid", "user-2")
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409 (already claimed); body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestHITLClaim_TenantIsolation(t *testing.T) {
	t.Parallel()
	router, evRepo := newRouterWithSeededHITL(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")
	body := bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/claim", body)
	req.Header.Set("X-Tenant-Id", "tenant-2")
	req.Header.Set("gcid", "user-1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("cross-tenant: status = %d; want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHITLRelease_HappyPathReturns200(t *testing.T) {
	t.Parallel()
	router, evRepo := newRouterWithSeededHITL(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")

	body1 := bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/claim", body1)
	req1.Header.Set("X-Tenant-Id", "tenant-1")
	req1.Header.Set("gcid", "user-1")
	req1.Header.Set("Content-Type", "application/json")
	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("Claim: status = %d", rr1.Code)
	}

	body2 := bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/release", body2)
	req2.Header.Set("X-Tenant-Id", "tenant-1")
	req2.Header.Set("gcid", "user-1")
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("Release: status = %d; body=%s", rr2.Code, rr2.Body.String())
	}
	var resp struct {
		AssigneeGcid *string `json:"assignee_gcid"`
	}
	if err := json.NewDecoder(rr2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AssigneeGcid != nil {
		t.Errorf("assignee_gcid = %v; want null after release", resp.AssigneeGcid)
	}
}

func TestHITLRelease_NotAssigneeReturns403(t *testing.T) {
	t.Parallel()
	router, evRepo := newRouterWithSeededHITL(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")

	body1 := bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/claim", body1)
	req1.Header.Set("X-Tenant-Id", "tenant-1")
	req1.Header.Set("gcid", "user-1")
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), req1)

	body2 := bytes.NewBufferString(`{"operator_gcid":"bob-gcid"}`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/release", body2)
	req2.Header.Set("X-Tenant-Id", "tenant-1")
	req2.Header.Set("gcid", "user-2")
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("status = %d; want 403; body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestHITLRelease_NotFoundReturns404(t *testing.T) {
	t.Parallel()
	router, _ := newRouterWithSeededHITL(t)
	body := bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/missing/release", body)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404; body=%s", rr.Code, rr.Body.String())
	}
}

// -----------------------------------------------------------------------------
// /api/imda/dimensions/{name}/rubric
// -----------------------------------------------------------------------------

func TestDimensionRubric_RequiresGET(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/imda/dimensions/accountability/rubric", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rr.Code)
	}
}

func TestDimensionRubric_UnknownSubresource(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/imda/dimensions/accountability/notrubric", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rr.Code)
	}
}

func TestDimensionRubric_HappyPath(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/imda/dimensions/accountability/rubric", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Dimension string `json:"dimension"`
		Items     []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
		Total    int     `json:"total"`
		PassRate float64 `json:"pass_rate"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Dimension != "accountability" {
		t.Errorf("dimension = %q; want accountability", body.Dimension)
	}
	if body.Total != 2 {
		t.Errorf("total = %d; want 2", body.Total)
	}
	// PARTIAL + PASS → pass_rate = (0.5 + 1.0) / 2 = 0.75
	if body.PassRate < 0.74 || body.PassRate > 0.76 {
		t.Errorf("pass_rate = %f; want ~0.75", body.PassRate)
	}
}

func TestDimensionRubric_DeprecatedAliasAccepted(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	// risk_levels is the v1 alias for accountability.
	req := httptest.NewRequest(http.MethodGet, "/api/imda/dimensions/risk_levels/rubric", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (v1 alias should canonicalise)", rr.Code)
	}
	var body struct {
		Dimension string `json:"dimension"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Dimension != "accountability" {
		t.Errorf("dimension = %q; want canonical accountability", body.Dimension)
	}
}

func TestDimensionRubric_InvalidDimensionRejected(t *testing.T) {
	t.Parallel()
	router := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/imda/dimensions/nonsense/rubric", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rr.Code)
	}
}

func TestDimensionRubric_NoConfigEntriesReturns400(t *testing.T) {
	t.Parallel()
	// safety_and_robustness has no entries in rubricConfigForTest() — but
	// the dimension is canonical so it passes Valid(); the resolver returns
	// a "no config entries" error which the handler maps to 400.
	router := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/imda/dimensions/safety_and_robustness/rubric", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (no rubric config for dimension)", rr.Code)
	}
}

// -----------------------------------------------------------------------------
// /api/hitl/decisions/{id}/approve + /reject (verdict)
// -----------------------------------------------------------------------------

// recordingPublisher is a test double for httpadapter.AuditPublisher. It
// captures each PublishWithError call so tests can assert the governance audit
// event was emitted.
type recordingPublisher struct {
	calls []struct {
		Topic   string
		Header  govevents.Header
		Payload map[string]interface{}
	}
}

func (p *recordingPublisher) PublishWithError(topic string, h govevents.Header, payload map[string]interface{}) (govevents.PublishedEvent, error) {
	p.calls = append(p.calls, struct {
		Topic   string
		Header  govevents.Header
		Payload map[string]interface{}
	}{topic, h, payload})
	return govevents.PublishedEvent{Topic: topic, TenantID: h.TenantID}, nil
}

// newRouterWithVerdictDeps wires a router with the evidence repo + audit repo +
// a recording publisher so approve/reject tests can assert all three effects.
func newRouterWithVerdictDeps(t *testing.T) (http.Handler, *evidence.InMemoryRepository, audit.Repository, *recordingPublisher) {
	t.Helper()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := domainimda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	evaluator := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	resolver, err := rubric.NewResolver(rubricConfigForTest(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	pub := &recordingPublisher{}
	router := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:     policyRepo,
		AuditRepo:      auditRepo,
		IMDARepo:       imdaRepo,
		Evaluator:      evaluator,
		EvidenceRepo:   evRepo,
		RubricResolver: resolver,
		AuditPublisher: pub,
	})
	return router, evRepo, auditRepo, pub
}

func postVerdict(t *testing.T, router http.Handler, action, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/"+action, bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestHITLApprove_HappyPathReturns200(t *testing.T) {
	t.Parallel()
	router, evRepo, auditRepo, pub := newRouterWithVerdictDeps(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")

	rr := postVerdict(t, router, "approve", `{"operator_gcid":"alice-gcid","note":"verified"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		DecisionID   string `json:"decision_id"`
		Decision     string `json:"decision"`
		OperatorGcid string `json:"operator_gcid"`
		Note         string `json:"note"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Decision != "approve" {
		t.Errorf("decision = %q; want approve", resp.Decision)
	}
	if resp.OperatorGcid != "alice-gcid" {
		t.Errorf("operator_gcid = %q; want alice-gcid", resp.OperatorGcid)
	}
	if resp.Note != "verified" {
		t.Errorf("note = %q; want verified", resp.Note)
	}

	// Verdict appended to the evidence repo (append-only).
	loaded, err := evRepo.LoadHITLDecision(context.Background(), "tenant-1", "dec-1")
	if err != nil {
		t.Fatalf("LoadHITLDecision: %v", err)
	}
	if loaded.Decision != evidence.HitlApprove {
		t.Errorf("persisted decision = %q; want approve", loaded.Decision)
	}

	// Hash-chained audit row written.
	auditRows, err := auditRepo.Query(context.Background(), audit.QueryFilter{TenantID: "tenant-1"})
	if err != nil {
		t.Fatalf("audit Query: %v", err)
	}
	if len(auditRows) != 1 {
		t.Fatalf("audit rows = %d; want 1", len(auditRows))
	}
	if auditRows[0].Decision != audit.DecisionPermitted {
		t.Errorf("audit decision = %q; want permitted", auditRows[0].Decision)
	}

	// Governance audit event published to the outbox.
	if len(pub.calls) != 1 {
		t.Fatalf("publisher calls = %d; want 1", len(pub.calls))
	}
	if pub.calls[0].Topic != govevents.TopicAuditRecorded {
		t.Errorf("topic = %q; want %q", pub.calls[0].Topic, govevents.TopicAuditRecorded)
	}
	if got := pub.calls[0].Payload["result"]; got != 1 {
		t.Errorf("payload[result] = %v; want 1 (ALLOWED)", got)
	}
}

func TestHITLReject_HappyPathReturns200(t *testing.T) {
	t.Parallel()
	router, evRepo, auditRepo, pub := newRouterWithVerdictDeps(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")

	rr := postVerdict(t, router, "reject", `{"operator_gcid":"bob-gcid"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rr.Code, rr.Body.String())
	}
	loaded, err := evRepo.LoadHITLDecision(context.Background(), "tenant-1", "dec-1")
	if err != nil {
		t.Fatalf("LoadHITLDecision: %v", err)
	}
	if loaded.Decision != evidence.HitlReject {
		t.Errorf("persisted decision = %q; want reject", loaded.Decision)
	}
	auditRows, _ := auditRepo.Query(context.Background(), audit.QueryFilter{TenantID: "tenant-1"})
	if len(auditRows) != 1 || auditRows[0].Decision != audit.DecisionDenied {
		t.Errorf("audit row = %+v; want 1 denied row", auditRows)
	}
	if len(pub.calls) != 1 || pub.calls[0].Payload["result"] != 2 {
		t.Errorf("publish result = %v; want 2 (DENIED)", pub.calls)
	}
}

func TestHITLApprove_RequiresPOST(t *testing.T) {
	t.Parallel()
	router, _, _, _ := newRouterWithVerdictDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/api/hitl/decisions/dec-1/approve", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rr.Code)
	}
}

func TestHITLApprove_BlankGcidReturns422(t *testing.T) {
	t.Parallel()
	router, evRepo, _, _ := newRouterWithVerdictDeps(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")
	rr := postVerdict(t, router, "approve", `{"operator_gcid":"  "}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHITLApprove_NotFoundReturns404(t *testing.T) {
	t.Parallel()
	router, _, _, _ := newRouterWithVerdictDeps(t)
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/missing/approve",
		bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`))
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404; body=%s", rr.Code, rr.Body.String())
	}
}

func TestHITLApprove_AlreadyDecidedReturns409(t *testing.T) {
	t.Parallel()
	router, evRepo, _, _ := newRouterWithVerdictDeps(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")

	if rr := postVerdict(t, router, "approve", `{"operator_gcid":"alice-gcid"}`); rr.Code != http.StatusOK {
		t.Fatalf("first approve: status = %d", rr.Code)
	}
	// Second verdict on the now-terminal gate ⇒ 409.
	rr2 := postVerdict(t, router, "reject", `{"operator_gcid":"bob-gcid"}`)
	if rr2.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409 (terminal verdict); body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestHITLApprove_TenantIsolationReturns404(t *testing.T) {
	t.Parallel()
	router, evRepo, _, _ := newRouterWithVerdictDeps(t)
	seedPendingHITLDecision(t, evRepo, "tenant-1", "dec-1")
	// Request scoped to a different tenant ⇒ 404, no existence leak.
	req := httptest.NewRequest(http.MethodPost, "/api/hitl/decisions/dec-1/approve",
		bytes.NewBufferString(`{"operator_gcid":"alice-gcid"}`))
	req.Header.Set("X-Tenant-Id", "tenant-2")
	req.Header.Set("gcid", "user-1")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404 (tenant isolation)", rr.Code)
	}
}

// CHO-2368 P2 — a pending prompt-plan gate card must surface agent_id +
// summary + created_at (the gateway's HITLPendingItem reads exactly those
// keys; without them the O+ card renders blank).
func TestHITLPending_SurfacesAgentSummaryCreatedAt(t *testing.T) {
	t.Parallel()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := domainimda.NewInMemoryRepository()
	evRepo := evidence.NewInMemoryRepository()
	evaluator := gatekeeper.NewEvaluator(policyRepo, auditRepo)

	pending, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       "ev-prompt-gate-1",
		TenantID:      "tenant-1",
		DecisionID:    "prompt-override-plan:plan-1",
		RunID:         "cho2368-qgen-question-prompt-1-1-0-r1",
		AutonomyLevel: evidence.AutonomyHitlL0,
		AgentID:       "prompt-registry",
		Summary:       "prompt override plan plan-1 passed eval - awaiting human sign-off",
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if err := evRepo.AppendHITLDecision(context.Background(), pending); err != nil {
		t.Fatalf("AppendHITLDecision: %v", err)
	}

	resolver, err := rubric.NewResolver(rubricConfigForTest(), evRepo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	dashboardSvc, err := usecaseimda.NewService(imdaRepo, resolver)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	router := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo:     policyRepo,
		AuditRepo:      auditRepo,
		IMDARepo:       imdaRepo,
		Evaluator:      evaluator,
		EvidenceRepo:   evRepo,
		RubricResolver: resolver,
		DashboardSvc:   dashboardSvc,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/hitl/pending", nil)
	req.Header.Set("X-Tenant-Id", "tenant-1")
	req.Header.Set("gcid", "user-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rr.Code)
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 1 {
		t.Fatalf("items = %d; want 1", len(body.Items))
	}
	item := body.Items[0]
	if got, _ := item["agent_id"].(string); got != "prompt-registry" {
		t.Errorf("agent_id = %q; want prompt-registry", got)
	}
	if got, _ := item["summary"].(string); got == "" {
		t.Error("summary missing; the card must show WHY the gate was raised")
	}
	created, _ := item["created_at"].(string)
	if created == "" {
		t.Fatal("created_at missing; the card's waiting-since renders zero-time without it")
	}
	if _, err := time.Parse(time.RFC3339, created); err != nil {
		t.Errorf("created_at %q is not RFC3339: %v", created, err)
	}
}
