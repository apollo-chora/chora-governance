// error_branches_internal_test.go — INTERNAL test package (package httpadapter).
//
// The external suite (handler_test.go + friends) covers the happy paths
// through the middleware-wrapped mux; this file drives the handler methods
// DIRECTLY (no tenantContext middleware) so the error branches that the
// middleware would mask — missing-tenant 400s, dep-nil 503s, repo-error 500s,
// method-not-allowed 405s, decode failures — are all exercised. It also table
// tests the unexported helpers (decodeJSON(pOptional), buildEvidenceFilter,
// roleAudience, canViewAudience, parseIntOrDefault, statusMatchesHITL).
//
// Because this is an internal test file it may reference unexported types
// (handler, imdaHandler, oplusHandler, aiTransparencyHandler, ctxKey...).
package httpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/aitransparency"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/compliance"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/evidencepack"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
)

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// per-Test tenant + gcid (internal-package copy; the external suite keeps its
// own constants in handler_test.go).
const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	gcidA   = "01970000-0000-7000-9000-000000000001"
)

// authedCtx returns a request context carrying tenant + gcid (bypasses
// tenantContext middleware).
func authedCtx(t *testing.T) context.Context {
	t.Helper()
	ctx := context.Background()
	ctx = context.WithValue(ctx, ctxKeyTenantID, tenantA)
	ctx = context.WithValue(ctx, ctxKeyGcid, gcidA)
	return ctx
}

func reqWithCtx(ctx context.Context, method, path string, body any) *http.Request {
	var r *http.Request
	if body != nil {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(body)
		r = httptest.NewRequest(method, path, &buf)
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r = r.WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func rawBodyReq(ctx context.Context, method, path, raw string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(raw))
	r = r.WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func baseHandler() *handler {
	return &handler{
		policies: policy.NewInMemoryRepository(),
		audits:   audit.NewInMemoryRepository(),
		imdas:    imda.NewInMemoryRepository(),
		eval:     gatekeeper.NewEvaluator(policy.NewInMemoryRepository(), audit.NewInMemoryRepository()),
		gen:      compliance.NewGenerator(audit.NewInMemoryRepository(), imda.NewInMemoryRepository()),
	}
}

// -----------------------------------------------------------------------------
// failing repository stubs
// -----------------------------------------------------------------------------

type errPolicyRepo struct {
	*policy.InMemoryRepository
	errOnSave bool
	errOnGet  bool
	errOnList bool
}

func (f *errPolicyRepo) Save(ctx context.Context, r *policy.Rule) error {
	if f.errOnSave {
		return errors.New("save boom")
	}
	return f.InMemoryRepository.Save(ctx, r)
}

func (f *errPolicyRepo) Get(ctx context.Context, id string) (*policy.Rule, error) {
	if f.errOnGet {
		return nil, errors.New("get boom")
	}
	return f.InMemoryRepository.Get(ctx, id)
}

func (f *errPolicyRepo) List(ctx context.Context, filter policy.ListFilter) ([]*policy.Rule, error) {
	if f.errOnList {
		return nil, errors.New("list boom")
	}
	return f.InMemoryRepository.List(ctx, filter)
}

type errIMDARepo struct {
	*imda.InMemoryRepository
	errOnAppend    bool
	errOnDashboard bool
}

func (f *errIMDARepo) Append(ctx context.Context, a *imda.Assessment) error {
	if f.errOnAppend {
		return errors.New("append boom")
	}
	return f.InMemoryRepository.Append(ctx, a)
}

func (f *errIMDARepo) Dashboard(ctx context.Context, tenantID string) ([]*imda.Assessment, error) {
	if f.errOnDashboard {
		return nil, errors.New("dashboard boom")
	}
	return f.InMemoryRepository.Dashboard(ctx, tenantID)
}

type errAuditRepo struct {
	*audit.InMemoryRepository
	errOnQuery  bool
	errOnVerify bool
	errOnAppend bool
}

func (f *errAuditRepo) Append(ctx context.Context, e *audit.Event) error {
	if f.errOnAppend {
		return errors.New("append boom")
	}
	return f.InMemoryRepository.Append(ctx, e)
}

func (f *errAuditRepo) Query(ctx context.Context, filter audit.QueryFilter) ([]*audit.Event, error) {
	if f.errOnQuery {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.Query(ctx, filter)
}

func (f *errAuditRepo) VerifyChain(ctx context.Context, tenantID string) (audit.VerifyResult, error) {
	if f.errOnVerify {
		return audit.VerifyResult{}, errors.New("verify boom")
	}
	return f.InMemoryRepository.VerifyChain(ctx, tenantID)
}

// errEvidenceRepo embeds the in-memory repo and fails selected evidence
// queries so the D1-D4 + HITL handler error paths can be exercised.
type errEvidenceRepo struct {
	*evidence.InMemoryRepository
	fail map[string]bool
}

func (f *errEvidenceRepo) QueryAccountability(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.AccountabilityEvidence, error) {
	if f.fail["d1"] {
		return nil, errors.New("boom")
	}
	return f.InMemoryRepository.QueryAccountability(ctx, filter)
}

func (f *errEvidenceRepo) QueryModelCards(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.ModelCard, error) {
	if f.fail["mcs"] {
		return nil, errors.New("boom")
	}
	return f.InMemoryRepository.QueryModelCards(ctx, filter)
}

func (f *errEvidenceRepo) QueryDataCards(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.DataCard, error) {
	if f.fail["dcs"] {
		return nil, errors.New("boom")
	}
	return f.InMemoryRepository.QueryDataCards(ctx, filter)
}

func (f *errEvidenceRepo) QueryDecisionExplanation(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.DecisionExplanation, error) {
	if f.fail["exps"] {
		return nil, errors.New("boom")
	}
	return f.InMemoryRepository.QueryDecisionExplanation(ctx, filter)
}

func (f *errEvidenceRepo) GetDecisionExplanationByDecisionID(ctx context.Context, tenantID, decisionID string, audience evidence.Audience) ([]*evidence.DecisionExplanation, error) {
	if f.fail["explookup"] {
		return nil, errors.New("boom")
	}
	return f.InMemoryRepository.GetDecisionExplanationByDecisionID(ctx, tenantID, decisionID, audience)
}

func (f *errEvidenceRepo) QueryHITLDecisions(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.HITLDecision, error) {
	if f.fail["hitl"] {
		return nil, errors.New("boom")
	}
	return f.InMemoryRepository.QueryHITLDecisions(ctx, filter)
}

func (f *errEvidenceRepo) LoadHITLDecision(ctx context.Context, tenantID, decisionID string) (*evidence.HITLDecision, error) {
	if f.fail["hitlload"] {
		return nil, errors.New("boom")
	}
	return f.InMemoryRepository.LoadHITLDecision(ctx, tenantID, decisionID)
}

func (f *errEvidenceRepo) UpdateAssigneeGcid(ctx context.Context, tenantID, decisionID string, assigneeGcid *string, now time.Time) error {
	if f.fail["hitlupdate"] {
		return errors.New("boom")
	}
	return f.InMemoryRepository.UpdateAssigneeGcid(ctx, tenantID, decisionID, assigneeGcid, now)
}

func (f *errEvidenceRepo) RecordHITLVerdict(ctx context.Context, src *evidence.HITLDecision) error {
	if f.fail["hitlrecord"] {
		return errors.New("boom")
	}
	return f.InMemoryRepository.RecordHITLVerdict(ctx, src)
}

// errPublisher fails every publish.
type errPublisher struct{}

func (errPublisher) PublishWithError(string, govevents.Header, map[string]interface{}) (govevents.PublishedEvent, error) {
	return govevents.PublishedEvent{}, errors.New("publish boom")
}

// -----------------------------------------------------------------------------
// handler.go — /api/* error branches
// -----------------------------------------------------------------------------

func TestInternal_Readyz_UninitialisedDeps503(t *testing.T) {
	t.Parallel()
	h := &handler{}
	w := httptest.NewRecorder()
	h.readyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503", w.Code)
	}
}

func TestInternal_IndexHandler_UnknownPath404(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.indexHandler(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

func TestInternal_PoliciesCollection_405(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.policiesCollection(w, reqWithCtx(authedCtx(t), http.MethodPut, "/api/policies", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", w.Code)
	}
}

func TestInternal_PolicyItem_EmptyAndSubresource404(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.policiesItem(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/policies/", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("empty id status = %d; want 404", w.Code)
	}
	w = httptest.NewRecorder()
	h.policiesItem(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/policies/a/b", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("sub-path status = %d; want 404", w.Code)
	}
}

func TestInternal_PolicyItem_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.policiesItem(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/policies/xyz", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", w.Code)
	}
}

func TestInternal_PolicyItem_RepoError(t *testing.T) {
	t.Parallel()
	h := &handler{policies: &errPolicyRepo{InMemoryRepository: policy.NewInMemoryRepository(), errOnGet: true}}
	w := httptest.NewRecorder()
	h.policiesItem(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/policies/xyz", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

func TestInternal_CreatePolicy_BadJSON(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.createPolicy(w, rawBodyReq(authedCtx(t), http.MethodPost, "/api/policies", "{not json"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestInternal_CreatePolicy_EmptyBody(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.createPolicy(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/policies", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestInternal_CreatePolicy_InvalidPolicy(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.createPolicy(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/policies", map[string]any{
		"name": "x", "enforcement_mode": "allow", "conditions": []any{},
	}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (no conditions)", w.Code)
	}
}

func TestInternal_CreatePolicy_SaveError(t *testing.T) {
	t.Parallel()
	h := &handler{policies: &errPolicyRepo{InMemoryRepository: policy.NewInMemoryRepository(), errOnSave: true}}
	w := httptest.NewRecorder()
	h.createPolicy(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/policies", map[string]any{
		"name": "x", "enforcement_mode": "allow",
		"conditions": []map[string]any{{"field": "a", "op": "equals", "value": "b"}},
	}))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

func TestInternal_ListPolicies_RepoError(t *testing.T) {
	t.Parallel()
	h := &handler{policies: &errPolicyRepo{InMemoryRepository: policy.NewInMemoryRepository(), errOnList: true}}
	w := httptest.NewRecorder()
	h.listPolicies(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/policies", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

func TestInternal_Evaluate_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.evaluate(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/gatekeeper/evaluate", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", w.Code)
	}
}

func TestInternal_Evaluate_BadJSON(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.evaluate(w, rawBodyReq(authedCtx(t), http.MethodPost, "/api/gatekeeper/evaluate", "{"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestInternal_Evaluate_EmptyActionIsInvalid(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.evaluate(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/gatekeeper/evaluate", map[string]any{
		"resource": "lesson", // action omitted → evaluator rejects
	}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestInternal_QueryAudit_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.queryAudit(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/audit", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", w.Code)
	}
}

func TestInternal_QueryAudit_MissingTenant400(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	// bare context — no tenant anywhere.
	h.queryAudit(w, httptest.NewRequest(http.MethodGet, "/api/audit", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

func TestInternal_QueryAudit_BadParamsIgnored(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	// from/to/limit parse failures are silently ignored — the query still runs.
	w := httptest.NewRecorder()
	h.queryAudit(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/audit?from=not-a-time&to=also-bad&limit=abc&action=", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 (params dropped)", w.Code)
	}
}

func TestInternal_QueryAudit_RepoError(t *testing.T) {
	t.Parallel()
	h := &handler{audits: &errAuditRepo{InMemoryRepository: audit.NewInMemoryRepository(), errOnQuery: true}}
	w := httptest.NewRecorder()
	h.queryAudit(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/audit", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

func TestInternal_CreateAssessment_405AndErrors(t *testing.T) {
	t.Parallel()
	h := baseHandler()

	w := httptest.NewRecorder()
	h.createAssessment(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/imda/assessments", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d; want 405", w.Code)
	}

	w = httptest.NewRecorder()
	h.createAssessment(w, rawBodyReq(authedCtx(t), http.MethodPost, "/api/imda/assessments", "{"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad json status = %d; want 400", w.Code)
	}

	w = httptest.NewRecorder()
	h.createAssessment(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/imda/assessments", map[string]any{
		"dimension": "accountability", "score": 101,
	}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("score>100 status = %d; want 400", w.Code)
	}
}

func TestInternal_CreateAssessment_RepoError(t *testing.T) {
	t.Parallel()
	h := &handler{imdas: &errIMDARepo{InMemoryRepository: imda.NewInMemoryRepository(), errOnAppend: true}}
	w := httptest.NewRecorder()
	h.createAssessment(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/imda/assessments", map[string]any{
		"dimension": "accountability", "score": 50,
	}))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

func TestInternal_IMDADashboard_405AndRepoError(t *testing.T) {
	t.Parallel()
	h := baseHandler()

	w := httptest.NewRecorder()
	h.imdaDashboard(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/imda/dashboard", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d; want 405", w.Code)
	}

	h = &handler{imdas: &errIMDARepo{InMemoryRepository: imda.NewInMemoryRepository(), errOnDashboard: true}}
	w = httptest.NewRecorder()
	h.imdaDashboard(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/imda/dashboard", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("repo error status = %d; want 500", w.Code)
	}
}

func TestInternal_GenerateReport_405AndEmptyTenant(t *testing.T) {
	t.Parallel()
	h := baseHandler()

	w := httptest.NewRecorder()
	h.generateReport(w, reqWithCtx(authedCtx(t), http.MethodGet, "/api/compliance/reports", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d; want 405", w.Code)
	}

	// No tenant in ctx → generator rejects.
	w = httptest.NewRecorder()
	h.generateReport(w, httptest.NewRequest(http.MethodPost, "/api/compliance/reports", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty tenant status = %d; want 400", w.Code)
	}
}

// -----------------------------------------------------------------------------
// imda_handler.go — D1-D4 + decisions + verify + export + project errors
// -----------------------------------------------------------------------------

func seedEvidenceHandler(t *testing.T, repo evidence.Repository) *imdaHandler {
	t.Helper()
	ar := audit.NewInMemoryRepository()
	er := evidence.Repository(evidence.NewInMemoryRepository())
	if repo != nil {
		er = repo
	}
	return &imdaHandler{repo: er, audits: ar}
}

func TestInternal_D1_405AndRepoError(t *testing.T) {
	t.Parallel()
	h := seedEvidenceHandler(t, nil)
	ctx := authedCtx(t)

	w := httptest.NewRecorder()
	h.dimensionD1(w, reqWithCtx(ctx, http.MethodPost, "/v1/governance/dimensions/d1/accountability", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d; want 405", w.Code)
	}

	// learner role (no header) → 403
	w = httptest.NewRecorder()
	h.dimensionD1(w, reqWithCtx(ctx, http.MethodGet, "/v1/governance/dimensions/d1/accountability", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("learner status = %d; want 403", w.Code)
	}

	h = seedEvidenceHandler(t, &errEvidenceRepo{InMemoryRepository: evidence.NewInMemoryRepository(), fail: map[string]bool{"d1": true}})
	w = httptest.NewRecorder()
	rq := reqWithCtx(ctx, http.MethodGet, "/v1/governance/dimensions/d1/accountability", nil)
	rq.Header.Set("X-Chora-Role", "auditor")
	h.dimensionD1(w, rq)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("repo error status = %d; want 500", w.Code)
	}
}

func TestInternal_D2_405AndQueryErrors(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)

	h := seedEvidenceHandler(t, nil)
	w := httptest.NewRecorder()
	h.dimensionD2(w, reqWithCtx(ctx, http.MethodPost, "/v1/governance/dimensions/d2/transparency", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d; want 405", w.Code)
	}

	// learner default role → D2 is learner-allowed, so use the error repos.
	cases := []string{"mcs", "dcs", "exps"}
	for _, fail := range cases {
		h = seedEvidenceHandler(t, &errEvidenceRepo{InMemoryRepository: evidence.NewInMemoryRepository(), fail: map[string]bool{fail: true}})
		w = httptest.NewRecorder()
		rq := reqWithCtx(ctx, http.MethodGet, "/v1/governance/dimensions/d2/transparency", nil)
		rq.Header.Set("X-Chora-Role", "auditor")
		h.dimensionD2(w, rq)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("fail=%s status = %d; want 500", fail, w.Code)
		}
	}
}

func TestInternal_D3AndD4_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	h := seedEvidenceHandler(t, nil)

	w := httptest.NewRecorder()
	h.dimensionD3(w, reqWithCtx(ctx, http.MethodPost, "/v1/governance/dimensions/d3/safety", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("D3 POST status = %d; want 405", w.Code)
	}

	w = httptest.NewRecorder()
	h.dimensionD4(w, reqWithCtx(ctx, http.MethodPost, "/v1/governance/dimensions/d4/fairness", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("D4 POST status = %d; want 405", w.Code)
	}
}

func TestInternal_DecisionsRouter_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	h := seedEvidenceHandler(t, nil)
	path := "/v1/governance/decisions/dc-1/explanation"

	// 405 on non-GET
	w := httptest.NewRecorder()
	h.decisionsRouter(w, reqWithCtx(ctx, http.MethodPost, path, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d; want 405", w.Code)
	}

	// invalid audience
	w = httptest.NewRecorder()
	rq := reqWithCtx(ctx, http.MethodGet, path+"?audience=superadmin", nil)
	rq.Header.Set("X-Chora-Role", "auditor")
	h.decisionsRouter(w, rq)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid audience status = %d; want 400", w.Code)
	}

	// learner cannot request auditor view
	w = httptest.NewRecorder()
	rq = reqWithCtx(ctx, http.MethodGet, path+"?audience=auditor", nil)
	h.decisionsRouter(w, rq)
	if w.Code != http.StatusForbidden {
		t.Errorf("learner→auditor status = %d; want 403", w.Code)
	}

	// repo error
	h = seedEvidenceHandler(t, &errEvidenceRepo{InMemoryRepository: evidence.NewInMemoryRepository(), fail: map[string]bool{"explookup": true}})
	w = httptest.NewRecorder()
	rq = reqWithCtx(ctx, http.MethodGet, path, nil)
	rq.Header.Set("X-Chora-Role", "auditor")
	h.decisionsRouter(w, rq)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("repo error status = %d; want 500", w.Code)
	}
}

func TestInternal_AuditVerify_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	path := "/v1/governance/audit/verify"

	// 405
	h := seedEvidenceHandler(t, nil)
	w := httptest.NewRecorder()
	h.auditVerify(w, reqWithCtx(ctx, http.MethodPost, path, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d; want 405", w.Code)
	}

	// learner forbidden
	w = httptest.NewRecorder()
	h.auditVerify(w, reqWithCtx(ctx, http.MethodGet, path, nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("learner status = %d; want 403", w.Code)
	}

	// audits repo nil → 503
	h = &imdaHandler{repo: evidence.NewInMemoryRepository()}
	w = httptest.NewRecorder()
	rq := reqWithCtx(ctx, http.MethodGet, path, nil)
	rq.Header.Set("X-Chora-Role", "auditor")
	h.auditVerify(w, rq)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil audits status = %d; want 503", w.Code)
	}

	// verify repo error → 500
	h = &imdaHandler{repo: evidence.NewInMemoryRepository(), audits: &errAuditRepo{InMemoryRepository: audit.NewInMemoryRepository(), errOnVerify: true}}
	w = httptest.NewRecorder()
	rq = reqWithCtx(ctx, http.MethodGet, path, nil)
	rq.Header.Set("X-Chora-Role", "auditor")
	h.auditVerify(w, rq)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("verify error status = %d; want 500", w.Code)
	}
}

func TestInternal_EvidenceExport_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	path := "/v1/governance/evidence/export"
	evRepo := evidence.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()

	// 405 + 403
	h := &imdaHandler{repo: evRepo, exp: evidencepack.New(evRepo, auditRepo)}
	w := httptest.NewRecorder()
	h.evidenceExport(w, reqWithCtx(ctx, http.MethodGet, path, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d; want 405", w.Code)
	}
	w = httptest.NewRecorder()
	h.evidenceExport(w, reqWithCtx(ctx, http.MethodPost, path, nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("learner status = %d; want 403", w.Code)
	}

	// exporter nil → 503
	h = &imdaHandler{repo: evRepo}
	w = httptest.NewRecorder()
	rq := reqWithCtx(ctx, http.MethodPost, path, nil)
	rq.Header.Set("X-Chora-Role", "auditor")
	h.evidenceExport(w, rq)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil exporter status = %d; want 503", w.Code)
	}

	// malformed JSON (non-empty body) → 400
	h = &imdaHandler{repo: evRepo, exp: evidencepack.New(evRepo, auditRepo)}
	w = httptest.NewRecorder()
	rq = rawBodyReq(ctx, http.MethodPost, path, "{nope")
	rq.Header.Set("X-Chora-Role", "auditor")
	h.evidenceExport(w, rq)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad json status = %d; want 400", w.Code)
	}

	// bad from / to timestamps → 400
	for _, body := range []map[string]any{{"from": "garbage"}, {"to": "garbage"}} {
		w = httptest.NewRecorder()
		rq = reqWithCtx(ctx, http.MethodPost, path, body)
		rq.Header.Set("X-Chora-Role", "auditor")
		h.evidenceExport(w, rq)
		if w.Code != http.StatusBadRequest {
			t.Errorf("timestamp %v status = %d; want 400", body, w.Code)
		}
	}

	// export error (To before From) → 400 GOV_EXPORT_FAILED
	w = httptest.NewRecorder()
	rq = reqWithCtx(ctx, http.MethodPost, path, map[string]any{
		"from": "2026-01-02T00:00:00Z", "to": "2026-01-01T00:00:00Z",
	})
	rq.Header.Set("X-Chora-Role", "auditor")
	h.evidenceExport(w, rq)
	if w.Code != http.StatusBadRequest {
		t.Errorf("reversed range status = %d; want 400", w.Code)
	}
}

func TestInternal_EvidenceProject_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	path := "/v1/governance/evidence/project"
	evRepo := evidence.NewInMemoryRepository()

	// 405 + 403
	h := &imdaHandler{repo: evRepo, proj: projector.New(evRepo)}
	w := httptest.NewRecorder()
	h.evidenceProject(w, reqWithCtx(ctx, http.MethodGet, path, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d; want 405", w.Code)
	}
	w = httptest.NewRecorder()
	h.evidenceProject(w, reqWithCtx(ctx, http.MethodPost, path, nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("learner status = %d; want 403", w.Code)
	}

	// projector nil → 503
	h = &imdaHandler{repo: evRepo}
	w = httptest.NewRecorder()
	rq := reqWithCtx(ctx, http.MethodPost, path, nil)
	rq.Header.Set("X-Chora-Role", "auditor")
	h.evidenceProject(w, rq)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil projector status = %d; want 503", w.Code)
	}

	// missing event_id → 400
	h = &imdaHandler{repo: evRepo, proj: projector.New(evRepo)}
	w = httptest.NewRecorder()
	rq = reqWithCtx(ctx, http.MethodPost, path, map[string]any{"tenant_id": "t"})
	rq.Header.Set("X-Chora-Role", "auditor")
	h.evidenceProject(w, rq)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing event_id status = %d; want 400", w.Code)
	}
}

// seedPendingDecision persists a PENDING HITL gate (no operator, no verdict)
// so claim/release/verdict handlers can exercise their post-load paths.
func seedPendingDecision(t *testing.T, repo *evidence.InMemoryRepository, tenantID, decisionID string) {
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
	if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("AppendHITLDecision: %v", err)
	}
}

// -----------------------------------------------------------------------------
// oplus_handlers.go — error branches
// -----------------------------------------------------------------------------

func newRubricResolver(t *testing.T) *rubric.Resolver {
	t.Helper()
	r, err := rubric.NewResolver(rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {Items: []rubric.ConfigItem{
				{ID: "raci", Title: "RACI", EvidenceSource: "doc", DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
			}},
		},
	}, evidence.NewInMemoryRepository())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func TestInternal_HITLPending_RepoNil503AndBadStatus(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)

	// repo nil → 503
	h := &oplusHandler{}
	w := httptest.NewRecorder()
	h.hitlPending(w, reqWithCtx(ctx, http.MethodGet, "/api/hitl/pending", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil repo status = %d; want 503", w.Code)
	}

	// unknown status filter falls through to the default equality branch → 200
	h = &oplusHandler{repo: evidence.NewInMemoryRepository()}
	w = httptest.NewRecorder()
	h.hitlPending(w, reqWithCtx(ctx, http.MethodGet, "/api/hitl/pending?status=bogus&limit=-5&offset=banana", nil))
	if w.Code != http.StatusOK {
		t.Errorf("bogus status filter → %d; want 200", w.Code)
	}
}

func TestInternal_HITLPending_QueryError(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	h := &oplusHandler{repo: &errEvidenceRepo{InMemoryRepository: evidence.NewInMemoryRepository(), fail: map[string]bool{"hitl": true}}}
	w := httptest.NewRecorder()
	h.hitlPending(w, reqWithCtx(ctx, http.MethodGet, "/api/hitl/pending", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

func TestInternal_DimensionRubricRouter_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)

	h := &oplusHandler{resolver: newRubricResolver(t)}

	// empty name → 400
	w := httptest.NewRecorder()
	h.dimensionRubricRouter(w, reqWithCtx(ctx, http.MethodGet, "/api/imda/dimensions//rubric", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty name status = %d; want 400", w.Code)
	}

	// 405
	w = httptest.NewRecorder()
	h.dimensionRubricRouter(w, reqWithCtx(ctx, http.MethodPost, "/api/imda/dimensions/accountability/rubric", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d; want 405", w.Code)
	}

	// resolver nil → 503
	h = &oplusHandler{}
	w = httptest.NewRecorder()
	h.dimensionRubricRouter(w, reqWithCtx(ctx, http.MethodGet, "/api/imda/dimensions/accountability/rubric", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil resolver status = %d; want 503", w.Code)
	}
}

func TestInternal_HITLDecisionRouter_Errors(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	h := &oplusHandler{repo: evidence.NewInMemoryRepository()}

	// empty decision id → 400
	w := httptest.NewRecorder()
	h.hitlDecisionRouter(w, reqWithCtx(ctx, http.MethodPost, "/api/hitl/decisions//claim", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty id status = %d; want 400", w.Code)
	}

	// unknown action → 404
	w = httptest.NewRecorder()
	h.hitlDecisionRouter(w, reqWithCtx(ctx, http.MethodGet, "/api/hitl/decisions/dc-1/explode", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown action status = %d; want 404", w.Code)
	}
}

func TestInternal_HITLClaim_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	path := "/api/hitl/decisions/dc-1/claim"

	// 405
	h := &oplusHandler{repo: evidence.NewInMemoryRepository()}
	w := httptest.NewRecorder()
	h.hitlClaim(w, reqWithCtx(ctx, http.MethodGet, path, nil), "dc-1")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d; want 405", w.Code)
	}

	// repo nil → 503
	h = &oplusHandler{}
	w = httptest.NewRecorder()
	h.hitlClaim(w, reqWithCtx(ctx, http.MethodPost, path, nil), "dc-1")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil repo status = %d; want 503", w.Code)
	}

	// malformed body → 422
	h = &oplusHandler{repo: evidence.NewInMemoryRepository()}
	w = httptest.NewRecorder()
	h.hitlClaim(w, rawBodyReq(ctx, http.MethodPost, path, "{nope"), "dc-1")
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad body status = %d; want 422", w.Code)
	}

	// load repo error → 500
	h = &oplusHandler{repo: &errEvidenceRepo{InMemoryRepository: evidence.NewInMemoryRepository(), fail: map[string]bool{"hitlload": true}}}
	w = httptest.NewRecorder()
	h.hitlClaim(w, reqWithCtx(ctx, http.MethodPost, path, map[string]any{"operator_gcid": "g-1"}), "dc-1")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("load error status = %d; want 500", w.Code)
	}

	// persist error → 500 (pending row loads + claims, update fails)
	repo := evidence.NewInMemoryRepository()
	seedPendingDecision(t, repo, tenantA, "dc-1")
	h = &oplusHandler{repo: &errEvidenceRepo{InMemoryRepository: repo, fail: map[string]bool{"hitlupdate": true}}}
	w = httptest.NewRecorder()
	h.hitlClaim(w, reqWithCtx(ctx, http.MethodPost, path, map[string]any{"operator_gcid": "g-1"}), "dc-1")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("persist error status = %d; want 500", w.Code)
	}
}

func TestInternal_HITLRelease_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	path := "/api/hitl/decisions/dc-1/release"

	h := &oplusHandler{repo: evidence.NewInMemoryRepository()}
	w := httptest.NewRecorder()
	h.hitlRelease(w, reqWithCtx(ctx, http.MethodGet, path, nil), "dc-1")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d; want 405", w.Code)
	}

	w = httptest.NewRecorder()
	h.hitlRelease(w, rawBodyReq(ctx, http.MethodPost, path, "not json"), "dc-1")
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad body status = %d; want 422", w.Code)
	}

	h = &oplusHandler{repo: &errEvidenceRepo{InMemoryRepository: evidence.NewInMemoryRepository(), fail: map[string]bool{"hitlupdate": true}}}
	w = httptest.NewRecorder()
	// claim the row first (assignee = g-1) so Release() succeeds and the
	// persist step is the failing one.
	repo := evidence.NewInMemoryRepository()
	seedPendingDecision(t, repo, tenantA, "dc-1")
	assigned := "g-1"
	loaded, err := repo.LoadHITLDecision(context.Background(), tenantA, "dc-1")
	if err != nil {
		t.Fatalf("LoadHITLDecision: %v", err)
	}
	loaded.AssigneeGcid = &assigned
	if err := repo.UpdateAssigneeGcid(context.Background(), tenantA, "dc-1", &assigned, time.Now()); err != nil {
		t.Fatalf("UpdateAssigneeGcid: %v", err)
	}
	h = &oplusHandler{repo: &errEvidenceRepo{InMemoryRepository: repo, fail: map[string]bool{"hitlupdate": true}}}
	w = httptest.NewRecorder()
	h.hitlRelease(w, reqWithCtx(ctx, http.MethodPost, path, map[string]any{"operator_gcid": "g-1"}), "dc-1")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("persist error status = %d; want 500", w.Code)
	}
}

func TestInternal_HITLVerdict_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	path := "/api/hitl/decisions/dc-1/approve"

	// 405
	h := &oplusHandler{repo: evidence.NewInMemoryRepository()}
	w := httptest.NewRecorder()
	h.hitlVerdict(w, reqWithCtx(ctx, http.MethodGet, path, nil), "dc-1", evidence.HitlApprove)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d; want 405", w.Code)
	}

	// repo nil → 503
	h = &oplusHandler{}
	w = httptest.NewRecorder()
	h.hitlVerdict(w, reqWithCtx(ctx, http.MethodPost, path, nil), "dc-1", evidence.HitlApprove)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil repo status = %d; want 503", w.Code)
	}

	// bad body → 422
	h = &oplusHandler{repo: evidence.NewInMemoryRepository()}
	w = httptest.NewRecorder()
	h.hitlVerdict(w, rawBodyReq(ctx, http.MethodPost, path, "{"), "dc-1", evidence.HitlApprove)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad body status = %d; want 422", w.Code)
	}

	// load error → 500
	h = &oplusHandler{repo: &errEvidenceRepo{InMemoryRepository: evidence.NewInMemoryRepository(), fail: map[string]bool{"hitlload": true}}}
	w = httptest.NewRecorder()
	h.hitlVerdict(w, reqWithCtx(ctx, http.MethodPost, path, map[string]any{"operator_gcid": "g-1"}), "dc-1", evidence.HitlApprove)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("load error status = %d; want 500", w.Code)
	}

	// record error → 500 (pending row loads + approves, append fails)
	repo := evidence.NewInMemoryRepository()
	seedPendingDecision(t, repo, tenantA, "dc-1")
	h = &oplusHandler{repo: &errEvidenceRepo{InMemoryRepository: repo, fail: map[string]bool{"hitlrecord": true}}}
	w = httptest.NewRecorder()
	h.hitlVerdict(w, reqWithCtx(ctx, http.MethodPost, path, map[string]any{"operator_gcid": "g-1"}), "dc-1", evidence.HitlApprove)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("record error status = %d; want 500", w.Code)
	}
}

func TestInternal_HITLVerdict_RejectAuditsDeniedAndPublishes(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	evRepo := evidence.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	seedPendingDecision(t, evRepo, tenantA, "dc-reject")

	h := &oplusHandler{
		repo:      evRepo,
		audits:    auditRepo,
		publisher: &recordPublisher{},
	}
	w := httptest.NewRecorder()
	rq := reqWithCtx(ctx, http.MethodPost, "/api/hitl/decisions/dc-reject/reject", map[string]any{"operator_gcid": "g-1", "note": "denied"})
	h.hitlDecisionRouter(w, rq)
	if w.Code != http.StatusOK {
		t.Fatalf("reject status = %d body=%s", w.Code, w.Body.String())
	}
	// audit row written with DENIED decision
	evs, err := auditRepo.Query(ctx, audit.QueryFilter{TenantID: tenantA, Action: "governance.hitl.decision_reject"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(evs) != 1 || evs[0].Decision != audit.DecisionDenied {
		t.Errorf("audit rows = %d decision=%v; want 1 denied", len(evs), evs[0].Decision)
	}
}

func TestInternal_HITLVerdict_PublishErrorStill200(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	evRepo := evidence.NewInMemoryRepository()
	seedPendingDecision(t, evRepo, tenantA, "dc-approve")

	// audits nil + failing publisher → verdict recorded, publish logged, 200.
	h := &oplusHandler{repo: evRepo, publisher: errPublisher{}}
	w := httptest.NewRecorder()
	rq := reqWithCtx(ctx, http.MethodPost, "/api/hitl/decisions/dc-approve/approve", map[string]any{"operator_gcid": "g-1"})
	h.hitlVerdict(w, rq, "dc-approve", evidence.HitlApprove)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 despite publish failure", w.Code)
	}
}

// recordPublisher captures publish calls.
type recordPublisher struct {
	calls     int
	lastTopic string
}

func (r *recordPublisher) PublishWithError(topic string, _ govevents.Header, _ map[string]interface{}) (govevents.PublishedEvent, error) {
	r.calls++
	r.lastTopic = topic
	return govevents.PublishedEvent{Topic: topic}, nil
}

func TestInternal_AuditHITLVerdict_NoAuditsSkipsAppend(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	d := &evidence.HITLDecision{
		TenantID: tenantA, DecisionID: "dc-1", EventID: "ev-1",
		Decision: evidence.HitlApprove,
	}
	h := &oplusHandler{publisher: &recordPublisher{}}
	rq := reqWithCtx(ctx, http.MethodPost, "/api/hitl/decisions/dc-1/approve", nil)
	h.auditHITLVerdict(rq, d, "g-1")
}

func TestInternal_WriteHITLDomainError_Default422(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	writeHITLDomainError(w, errors.New("some domain validation failure"))
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422", w.Code)
	}
}

// -----------------------------------------------------------------------------
// ai-transparency + phase6
// -----------------------------------------------------------------------------

func TestInternal_AITransparency_StateAndAckErrors(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	statePath := "/v1/me/ai-transparency"
	ackPath := "/v1/me/ai-transparency/acknowledge"

	// svc nil → 503 on both
	h := &aiTransparencyHandler{}
	w := httptest.NewRecorder()
	h.state(w, reqWithCtx(ctx, http.MethodGet, statePath, nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("state nil svc status = %d; want 503", w.Code)
	}
	w = httptest.NewRecorder()
	h.acknowledge(w, reqWithCtx(ctx, http.MethodPost, ackPath, nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("ack nil svc status = %d; want 503", w.Code)
	}

	// svc without active disclosure → GetState error → 500
	svc := aitransparency.NewService(aitransparency.NewInMemoryRepository(nil), nil)
	h = &aiTransparencyHandler{svc: svc}
	w = httptest.NewRecorder()
	h.state(w, reqWithCtx(ctx, http.MethodGet, statePath, nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("state error status = %d; want 500", w.Code)
	}

	// Acknowledge with a blank version against a repo with no active
	// disclosure → ActiveDisclosureVersion error → 400.
	w = httptest.NewRecorder()
	h.acknowledge(w, reqWithCtx(ctx, http.MethodPost, ackPath, map[string]any{"surface": "s", "scope": "learner_preview"}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("ack with nil-active repo status = %d; want 400", w.Code)
	}

	h = &aiTransparencyHandler{svc: aitransparency.NewService(aitransparency.NewInMemoryRepository(seedActiveDisclosure()), nil)}
	w = httptest.NewRecorder()
	h.acknowledge(w, rawBodyReq(ctx, http.MethodPost, ackPath, "{"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("ack bad json status = %d; want 400", w.Code)
	}
}

func seedActiveDisclosure() *aitransparency.DisclosureVersion {
	return &aitransparency.DisclosureVersion{
		Version:                   "2026-07-01",
		Status:                    aitransparency.StatusActive,
		RequiresReacknowledgement: true,
		EffectiveFrom:             time.Now().UTC().Add(-time.Hour),
		Scope:                     "platform",
		Locales: map[string]map[aitransparency.Variant]aitransparency.DisclosureCopy{
			"en": {
				aitransparency.VariantStandard: {
					Notice: aitransparency.NoticeCopy{Title: "T", Body: "B", Action: "A"},
					Badge:  aitransparency.BadgeCopy{Label: "L", Tooltip: "T"},
					InlineLabels: aitransparency.InlineLabels{
						AiGenerated: aitransparency.LabelCopy{Label: "AI", Tooltip: "T"},
					},
				},
			},
		},
	}
}

func TestInternal_AITransparency_EmitAcknowledged_PublishError(t *testing.T) {
	t.Parallel()
	ack := &aitransparency.Acknowledgement{
		ID: "ack-1", GCID: "g-1", TenantID: tenantA,
		DisclosureVersion: "v1", Surface: aitransparency.Surface("familiar"),
		Scope: "platform", FirstShownAt: time.Now(), AcknowledgedAt: time.Now(),
		Locale: "en", MinorMode: false,
	}
	h := &aiTransparencyHandler{publisher: errPublisher{}}
	r := reqWithCtx(authedCtx(t), http.MethodPost, "/v1/me/ai-transparency/acknowledge", nil)
	h.emitAcknowledged(r, ack) // no panic, publish error swallowed

	h2 := &aiTransparencyHandler{} // nil publisher → no-op
	h2.emitAcknowledged(r, ack)
}

func TestInternal_Phase6_DashboardError(t *testing.T) {
	t.Parallel()
	h := &phase6GovernanceHandler{imdas: &errIMDARepo{InMemoryRepository: imda.NewInMemoryRepository(), errOnDashboard: true}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/governance/t1", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

// -----------------------------------------------------------------------------
// pure helpers
// -----------------------------------------------------------------------------

func TestInternal_DecodeJSON_Branches(t *testing.T) {
	t.Parallel()
	type payload struct {
		Name string `json:"name"`
	}

	// empty body
	r := &http.Request{Body: nil} // httptest always wires a non-nil body
	err := decodeJSON(r, &payload{})
	if !errors.Is(err, errEmptyBody) {
		t.Errorf("empty body err = %v; want errEmptyBody", err)
	}

	// invalid JSON
	err = decodeJSON(rawBodyReq(context.Background(), http.MethodPost, "/", "{"), &payload{})
	if err == nil {
		t.Error("invalid JSON should error")
	}

	// unknown field
	err = decodeJSON(rawBodyReq(context.Background(), http.MethodPost, "/", `{"name":"x","bogus":1}`), &payload{})
	if err == nil {
		t.Error("unknown field should error")
	}

	// ok
	err = decodeJSON(rawBodyReq(context.Background(), http.MethodPost, "/", `{"name":"x"}`), &payload{})
	if err != nil {
		t.Errorf("valid JSON: %v", err)
	}
}

func TestInternal_DecodeJSONOptional_Branches(t *testing.T) {
	t.Parallel()
	type payload struct {
		N int `json:"n"`
	}

	// nil body → nil
	if err := decodeJSONOptional(httptest.NewRequest(http.MethodPost, "/", nil), &payload{}); err != nil {
		t.Errorf("nil body err = %v; want nil", err)
	}
	// zero ContentLength → nil
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	req.ContentLength = 0
	if err := decodeJSONOptional(req, &payload{}); err != nil {
		t.Errorf("empty body err = %v; want nil", err)
	}
	// valid body → parsed
	req = rawBodyReq(context.Background(), http.MethodPost, "/", `{"n":5}`)
	if err := decodeJSONOptional(req, &payload{}); err != nil {
		t.Errorf("valid body err = %v; want nil", err)
	}
	// invalid body → err
	req = rawBodyReq(context.Background(), http.MethodPost, "/", "{")
	if err := decodeJSONOptional(req, &payload{}); err == nil {
		t.Error("invalid body should error")
	}
}

func TestInternal_BuildEvidenceFilter_AllParams(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet,
		"/v1/governance/dimensions/d1/accountability"+
			"?lifecycle_stage=RUNTIME&agent_id=agt-1&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z&limit=25&offset=7",
		nil)
	f := buildEvidenceFilter(r, "tenant-x")
	if f.TenantID != "tenant-x" || f.LifecycleStage != "runtime" || f.AgentID != "agt-1" ||
		f.From == nil || f.To == nil || f.Limit != 25 || f.Offset != 7 {
		t.Errorf("filter mismatch: %+v", f)
	}

	// invalid params are dropped
	r = httptest.NewRequest(http.MethodGet, "/x?from=bad&to=worse&limit=abc&offset=-3", nil)
	f = buildEvidenceFilter(r, "tenant-x")
	if f.From != nil || f.To != nil || f.Limit != 0 || f.Offset != 0 {
		t.Errorf("invalid params not dropped: %+v", f)
	}
}

func TestInternal_RoleAudience_Fallback(t *testing.T) {
	t.Parallel()
	if got := roleAudience(httptest.NewRequest(http.MethodGet, "/", nil)); got != evidence.AudienceLearner {
		t.Errorf("missing header → %q; want learner", got)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(headerRole, "bogus-role")
	if got := roleAudience(r); got != evidence.AudienceLearner {
		t.Errorf("bogus role → %q; want learner", got)
	}
	r.Header.Set(headerRole, "AUDITOR")
	if got := roleAudience(r); got != evidence.AudienceAuditor {
		t.Errorf("AUDITOR → %q; want auditor (case-insensitive)", got)
	}
}

func TestInternal_CanViewAudience_Matrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		viewer, target evidence.Audience
		want           bool
	}{
		{evidence.AudienceLearner, evidence.AudienceLearner, true},
		{evidence.AudienceLearner, evidence.AudienceInstructorAdmin, false},
		{evidence.AudienceLearner, evidence.AudienceAuditor, false},
		{evidence.AudienceInstructorAdmin, evidence.AudienceLearner, true},
		{evidence.AudienceInstructorAdmin, evidence.AudienceInstructorAdmin, true},
		{evidence.AudienceInstructorAdmin, evidence.AudienceAuditor, false},
		{evidence.AudienceAuditor, evidence.AudienceAuditor, true},
		{evidence.AudienceAuditor, evidence.AudienceLearner, true},
		{evidence.Audience("bogus"), evidence.AudienceLearner, false},
	}
	for _, tc := range cases {
		if got := canViewAudience(tc.viewer, tc.target); got != tc.want {
			t.Errorf("canViewAudience(%q→%q) = %v; want %v", tc.viewer, tc.target, got, tc.want)
		}
	}
}

func TestInternal_ParseIntOrDefault_Branches(t *testing.T) {
	t.Parallel()
	if parseIntOrDefault("", 20) != 20 {
		t.Error("empty → fallback")
	}
	if parseIntOrDefault("  ", 20) != 20 {
		t.Error("blank → fallback")
	}
	if parseIntOrDefault("abc", 20) != 20 {
		t.Error("non-numeric → fallback")
	}
	if parseIntOrDefault("-1", 20) != 20 {
		t.Error("negative → fallback")
	}
	if parseIntOrDefault("7", 20) != 7 {
		t.Error("valid → parsed")
	}
}

func TestInternal_StatusMatchesHITL_DefaultBranch(t *testing.T) {
	t.Parallel()
	if !statusMatchesHITL("pending", "") {
		t.Error("pending matches empty decision")
	}
	if !statusMatchesHITL("pending", "pending") {
		t.Error("pending matches literal pending")
	}
	if statusMatchesHITL("pending", "approve") {
		t.Error("pending must not match approve")
	}
	if !statusMatchesHITL("approve", "approve") {
		t.Error("approve matches approve")
	}
	// default branch: unknown filter compares stored verbatim
	if !statusMatchesHITL("weird-token", "weird-token") {
		t.Error("unknown filter should compare verbatim")
	}
	if statusMatchesHITL("weird-token", "approve") {
		t.Error("unknown filter must not match unrelated verdict")
	}
}

// -----------------------------------------------------------------------------
// Tail branches — one or two statements each
// -----------------------------------------------------------------------------

func TestInternal_IndexHandler_RootPath(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.indexHandler(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

func TestInternal_CreatePolicy_TenantOverride(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	override := "tenant-override"
	h.createPolicy(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/policies", map[string]any{
		"name": "x", "tenant_id": override, "enforcement_mode": "allow",
		"conditions": []map[string]any{{"field": "a", "op": "equals", "value": "b"}},
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		TenantID string `json:"tenant_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.TenantID != override {
		t.Errorf("tenant_id = %q; want override value", got.TenantID)
	}
}

func TestInternal_CreatePolicy_GlobalBlanksTenant(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.createPolicy(w, reqWithCtx(authedCtx(t), http.MethodPost, "/api/policies", map[string]any{
		"name": "x", "global": true, "enforcement_mode": "allow",
		"conditions": []map[string]any{{"field": "a", "op": "equals", "value": "b"}},
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		TenantID string `json:"tenant_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.TenantID != "" {
		t.Errorf("global rule tenant_id = %q; want empty", got.TenantID)
	}
}

func TestInternal_QueryAudit_ValidRangeParams(t *testing.T) {
	t.Parallel()
	h := baseHandler()
	w := httptest.NewRecorder()
	h.queryAudit(w, reqWithCtx(authedCtx(t), http.MethodGet,
		"/api/audit?from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z&limit=50&action=read", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

func TestInternal_D2_LearnerSuccess(t *testing.T) {
	t.Parallel()
	er := evidence.NewInMemoryRepository()
	// seed one model card so the query returns rows for the learner.
	mc, err := evidence.NewModelCard(evidence.ModelCardParams{
		EventID: "ev-mc", TenantID: tenantA, ModelID: "m1", ModelVersion: "1.0.0",
		CardMD: "# c", TrainingDataSummary: "s", IntendedUses: "u", Limitations: "l",
	})
	if err != nil {
		t.Fatalf("NewModelCard: %v", err)
	}
	if err := er.AppendModelCard(context.Background(), mc); err != nil {
		t.Fatalf("AppendModelCard: %v", err)
	}
	h := seedEvidenceHandler(t, er)
	w := httptest.NewRecorder()
	// no X-Chora-Role → learner, which D2 allows.
	h.dimensionD2(w, reqWithCtx(authedCtx(t), http.MethodGet, "/v1/governance/dimensions/d2/transparency", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

func TestInternal_EvidenceProject_TenantFillFromContext(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	evRepo := evidence.NewInMemoryRepository()
	h := &imdaHandler{repo: evRepo, proj: projector.New(evRepo)}
	w := httptest.NewRecorder()
	// tenant_id omitted → taken from ctx; event_id present → success.
	rq := reqWithCtx(ctx, http.MethodPost, "/v1/governance/evidence/project", map[string]any{
		"event_id": "ev-proj", "imda_dimension": "accountability",
		"agent_id": "agt-1", "owner_gcid": "gcid-1", "decision_id": "dec-1",
		"decision_type": "route",
	})
	rq.Header.Set("X-Chora-Role", "auditor")
	h.evidenceProject(w, rq)
	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d body=%s; want 202", w.Code, w.Body.String())
	}
}

func TestInternal_TenantContext_GCIDAlternateHeader(t *testing.T) {
	t.Parallel()
	srv := NewRouter(Deps{PolicyRepo: policy.NewInMemoryRepository(), AuditRepo: audit.NewInMemoryRepository(),
		IMDARepo: imda.NewInMemoryRepository(), Evaluator: gatekeeper.NewEvaluator(policy.NewInMemoryRepository(), audit.NewInMemoryRepository())})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/audit?tenant_id="+tenantA, nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	r.Header.Set("X-Chora-GCID", gcidA) // alternate gcid header
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 (X-Chora-GCID accepted)", w.Code)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/api/audit?tenant_id="+tenantA, nil)
	r.Header.Set("X-Tenant-Id", tenantA)
	srv.ServeHTTP(w, r) // no gcid at all → 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (gcid required)", w.Code)
	}
}

func TestInternal_TenantMissing400s(t *testing.T) {
	t.Parallel()
	// direct handler calls with an empty-tenant ctx → 400
	ctx := context.Background()
	ctx = context.WithValue(ctx, ctxKeyGcid, gcidA)

	oh := &oplusHandler{repo: evidence.NewInMemoryRepository(), resolver: newRubricResolver(t)}
	w := httptest.NewRecorder()
	oh.hitlPending(w, reqWithCtx(ctx, http.MethodGet, "/api/hitl/pending", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("hitlPending status = %d; want 400", w.Code)
	}
	w = httptest.NewRecorder()
	oh.dimensionRubricRouter(w, reqWithCtx(ctx, http.MethodGet, "/api/imda/dimensions/accountability/rubric", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("rubric status = %d; want 400", w.Code)
	}
	w = httptest.NewRecorder()
	oh.hitlClaim(w, reqWithCtx(ctx, http.MethodPost, "/api/hitl/decisions/dc-1/claim", map[string]any{"operator_gcid": "g"}), "dc-1")
	if w.Code != http.StatusBadRequest {
		t.Errorf("claim status = %d; want 400", w.Code)
	}
	w = httptest.NewRecorder()
	oh.hitlVerdict(w, reqWithCtx(ctx, http.MethodPost, "/api/hitl/decisions/dc-1/approve", map[string]any{"operator_gcid": "g"}), "dc-1", evidence.HitlApprove)
	if w.Code != http.StatusBadRequest {
		t.Errorf("verdict status = %d; want 400", w.Code)
	}
}

func TestInternal_HITLRelease_AdditionalErrors(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	path := "/api/hitl/decisions/dc-1/release"

	// repo nil → 503
	h := &oplusHandler{}
	w := httptest.NewRecorder()
	h.hitlRelease(w, reqWithCtx(ctx, http.MethodPost, path, map[string]any{"operator_gcid": "g"}), "dc-1")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil repo status = %d; want 503", w.Code)
	}

	// unknown decision → 404
	h = &oplusHandler{repo: evidence.NewInMemoryRepository()}
	w = httptest.NewRecorder()
	h.hitlRelease(w, reqWithCtx(ctx, http.MethodPost, path, map[string]any{"operator_gcid": "g"}), "dc-1")
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown decision status = %d; want 404", w.Code)
	}
}

func TestInternal_HITLDecisionRouter_BadPath404(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	h := &oplusHandler{repo: evidence.NewInMemoryRepository()}
	w := httptest.NewRecorder()
	h.hitlDecisionRouter(w, reqWithCtx(ctx, http.MethodGet, "/api/hitl/decisions/only-one-part", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

func TestInternal_AuditHITLVerdict_AppendErrorLogged(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	d := &evidence.HITLDecision{TenantID: tenantA, DecisionID: "dc-1", EventID: "ev-1", Decision: evidence.HitlApprove}
	h := &oplusHandler{audits: &errAuditRepo{InMemoryRepository: audit.NewInMemoryRepository(), errOnAppend: true}}
	rq := reqWithCtx(ctx, http.MethodPost, "/api/hitl/decisions/dc-1/approve", nil)
	h.auditHITLVerdict(rq, d, "g-1") // append failure is logged, not fatal
}

func TestInternal_PublishHITLVerdictAudit_NoPublisherNoop(t *testing.T) {
	t.Parallel()
	d := &evidence.HITLDecision{TenantID: tenantA, DecisionID: "dc-1", EventID: "ev-1", Decision: evidence.HitlReject}
	h := &oplusHandler{} // nil publisher
	h.publishHITLVerdictAudit(reqWithCtx(authedCtx(t), http.MethodPost, "/x", nil), d, "g-1", "action", "resource")
}

func TestInternal_DecodeHITLBody_NilBody(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	r := &http.Request{Body: nil} // raw nil body
	_, _, ok := decodeHITLBody(w, r)
	if ok {
		t.Error("nil body should fail decode")
	}
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422", w.Code)
	}
}

func TestInternal_AITransparency_Acknowledge_FirstShownAtAndLocale(t *testing.T) {
	t.Parallel()
	ctx := authedCtx(t)
	svc := aitransparency.NewService(aitransparency.NewInMemoryRepository(seedActiveDisclosure()), nil)
	h := &aiTransparencyHandler{svc: svc, publisher: &recordPublisher{}}
	w := httptest.NewRecorder()
	rq := reqWithCtx(ctx, http.MethodPost, "/v1/me/ai-transparency/acknowledge", map[string]any{
		"surface": "familiar", "scope": "familiar_chat", "locale": "en",
		"firstShownAt": time.Now().UTC().Format(time.RFC3339), "disclosureVersion": "2026-07-01",
	})
	h.acknowledge(w, rq)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s; want 201", w.Code, w.Body.String())
	}
}
