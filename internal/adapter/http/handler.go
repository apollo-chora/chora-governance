// Package httpadapter exposes the chora-governance REST surface.
//
// 8 endpoints per the spec:
//
//	GET  /healthz, /healthz/        — liveness
//	GET  /readyz                    — readiness
//	POST /api/policies              — create PolicyRule
//	GET  /api/policies/{id}         — fetch one
//	GET  /api/policies              — list
//	POST /api/gatekeeper/evaluate   — evaluate request, always emits AuditEvent
//	GET  /api/audit                 — query audit events (append-only)
//	POST /api/imda/assessments      — create IMDADimensionAssessment
//	GET  /api/imda/dashboard        — 4 dimension scores + indicators
//	POST /api/compliance/reports    — generate ComplianceReport (JSON placeholder)
//
// All /api/* endpoints require X-Tenant-Id + gcid headers (per spec).
package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	usecaseimda "github.com/apollo-chora/chora-governance/internal/usecase/imda"
)

// Deps groups the wiring for the router.
type Deps struct {
	PolicyRepo   policy.Repository
	AuditRepo    audit.Repository
	IMDARepo     imda.Repository
	Evaluator    *gatekeeper.Evaluator
	EvidenceRepo evidence.Repository    // optional — IMDA D1-D4 evidence
	Projector    *projector.Projector   // optional — synchronous projector entry
	Exporter     *evidencepack.Exporter // optional — evidence pack ZIP export

	// Phase B (O+ hydration plan atomic-napping-spring.md) — optional. Wired
	// from cmd/server/main.go when config/imda_rubric.yaml is present.
	RubricResolver *rubric.Resolver     // optional — rubric drilldown
	DashboardSvc   *usecaseimda.Service // optional — IMDA Dashboard (rubric + assessment hybrid)

	// AuditPublisher emits governance audit events to the transactional
	// outbox (chora.governance.audit.recorded.v1) so they reach Cloud
	// Pub/Sub via the dispatcher. Optional — when nil the HITL verdict
	// handlers still write the hash-chained audit_log row but DO NOT emit a
	// Pub/Sub event. Wired from cmd/server/main.go as the outbox.Publisher.
	// Also reused by the AI-transparency acknowledge handler (ADR-225).
	AuditPublisher AuditPublisher

	// AITransparencySvc serves the learner-self AI Transparency Notice
	// endpoints (ADR-225). Optional — routes are registered only when wired.
	AITransparencySvc *aitransparency.Service
}

// NewRouter wires the public mux and returns a fully composed http.Handler.
func NewRouter(d Deps) http.Handler {
	h := &handler{
		policies: d.PolicyRepo,
		audits:   d.AuditRepo,
		imdas:    d.IMDARepo,
		eval:     d.Evaluator,
		gen:      compliance.NewGenerator(d.AuditRepo, d.IMDARepo),
	}

	mux := http.NewServeMux()

	// Health + readiness — public.
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/healthz/", healthz)
	mux.HandleFunc("/health", healthz)
	mux.HandleFunc("/readyz", h.readyz)
	mux.HandleFunc("/", h.indexHandler)

	// /api/policies
	mux.HandleFunc("/api/policies", h.policiesCollection)
	mux.HandleFunc("/api/policies/", h.policiesItem)

	// /api/gatekeeper/evaluate
	mux.HandleFunc("/api/gatekeeper/evaluate", h.evaluate)

	// /api/audit
	mux.HandleFunc("/api/audit", h.queryAudit)

	// /api/imda
	mux.HandleFunc("/api/imda/assessments", h.createAssessment)
	mux.HandleFunc("/api/imda/dashboard", h.imdaDashboard)

	// /api/compliance/reports
	mux.HandleFunc("/api/compliance/reports", h.generateReport)

	// IMDA D1-D4 evidence routes (optional — wired only when deps present)
	if d.EvidenceRepo != nil {
		ih := &imdaHandler{
			repo:   d.EvidenceRepo,
			proj:   d.Projector,
			exp:    d.Exporter,
			audits: d.AuditRepo,
		}
		registerIMDARoutes(mux, ih)
	}

	// Phase B (O+ hydration plan atomic-napping-spring.md) — register
	// /api/hitl/pending + /api/imda/dimensions/{name}/rubric when the rubric
	// resolver + evidence repo are wired. Both endpoints degrade gracefully
	// (503 with explicit error envelope) when their deps are nil.
	if d.EvidenceRepo != nil || d.RubricResolver != nil {
		oh := &oplusHandler{
			repo:         d.EvidenceRepo,
			resolver:     d.RubricResolver,
			dashboardSvc: d.DashboardSvc,
			audits:       d.AuditRepo,
			publisher:    d.AuditPublisher,
		}
		registerOPlusRoutes(mux, oh)
	}

	// AI Transparency Notice (ADR-225) — learner-self routes, registered only
	// when the service is wired. Verbatim-proxied by the gateway from
	// /api/v1/me/ai-transparency[/acknowledge].
	if d.AITransparencySvc != nil {
		ath := &aiTransparencyHandler{svc: d.AITransparencySvc, publisher: d.AuditPublisher}
		mux.HandleFunc("/v1/me/ai-transparency", ath.state)
		mux.HandleFunc("/v1/me/ai-transparency/acknowledge", ath.acknowledge)
	}

	// Phase 6: GetGovernance endpoint — GET /governance/{tenant_id} returns
	// the IMDA Dashboard JSON for the named tenant. Added so the
	// chora-gateway HTTPUpstream.GetGovernance method has a concrete
	// downstream target. Same response shape as /api/imda/dashboard.
	mux.Handle("/governance/", newPhase6GovernanceHandler(d.IMDARepo))

	return logging(tenantContext(mux))
}

type handler struct {
	policies policy.Repository
	audits   audit.Repository
	imdas    imda.Repository
	eval     *gatekeeper.Evaluator
	gen      *compliance.Generator
}

// -----------------------------------------------------------------------------
// Health + readiness
// -----------------------------------------------------------------------------

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *handler) readyz(w http.ResponseWriter, _ *http.Request) {
	if h.policies == nil || h.audits == nil || h.imdas == nil || h.eval == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "deps-uninitialised"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (h *handler) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "chora-governance",
		"surface": "O+ Observability+",
		"domain":  "Governance",
		"project": resolveProject(),
	})
}

// -----------------------------------------------------------------------------
// /api/policies
// -----------------------------------------------------------------------------

type createPolicyRequest struct {
	Name            string             `json:"name"`
	TenantID        *string            `json:"tenant_id,omitempty"` // optional override (defaults to header)
	EnforcementMode string             `json:"enforcement_mode"`
	Conditions      []policy.Condition `json:"conditions"`
	Global          bool               `json:"global,omitempty"` // if true, ignore tenant scope
}

func (h *handler) policiesCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listPolicies(w, r)
	case http.MethodPost:
		h.createPolicy(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only GET and POST are supported on /api/policies")
	}
}

func (h *handler) policiesItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/policies/")
	id = strings.TrimSuffix(id, "/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusNotFound, "GOV_NOT_FOUND", "unknown sub-resource")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only GET is supported on /api/policies/{id}")
		return
	}
	rule, err := h.policies.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, policy.ErrNotFound) {
			writeError(w, http.StatusNotFound, "GOV_POLICY_NOT_FOUND", "policy rule not found")
			return
		}
		log.Printf("policy get error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (h *handler) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req createPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_BODY", err.Error())
		return
	}
	tenantID := tenantFromContext(r.Context())
	if req.Global {
		tenantID = ""
	} else if req.TenantID != nil {
		tenantID = *req.TenantID
	}
	rule, err := policy.New(policy.NewParams{
		Name:            req.Name,
		TenantID:        tenantID,
		EnforcementMode: policy.EnforcementMode(req.EnforcementMode),
		Conditions:      req.Conditions,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_POLICY", err.Error())
		return
	}
	if err := h.policies.Save(r.Context(), rule); err != nil {
		log.Printf("policy save error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "failed to persist policy")
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

type listResponse struct {
	Items any `json:"items"`
	Total int `json:"total"`
}

func (h *handler) listPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	rules, err := h.policies.List(r.Context(), policy.ListFilter{TenantID: tenantID})
	if err != nil {
		log.Printf("policy list error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "failed to list policies")
		return
	}
	writeJSON(w, http.StatusOK, listResponse{Items: rules, Total: len(rules)})
}

// -----------------------------------------------------------------------------
// /api/gatekeeper/evaluate
// -----------------------------------------------------------------------------

type evaluateRequest struct {
	Action   string         `json:"action"`
	Resource string         `json:"resource"`
	Agid     string         `json:"agid,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

func (h *handler) evaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only POST is supported on /api/gatekeeper/evaluate")
		return
	}
	var req evaluateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_BODY", err.Error())
		return
	}
	tenantID := tenantFromContext(r.Context())
	gcid := gcidFromContext(r.Context())
	d, err := h.eval.Evaluate(r.Context(), gatekeeper.Request{
		TenantID:    tenantID,
		Gcid:        gcid,
		Agid:        req.Agid,
		Action:      req.Action,
		Resource:    req.Resource,
		Context:     req.Context,
		Traceparent: r.Header.Get("traceparent"),
		Tracestate:  r.Header.Get("tracestate"),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "GOV_EVALUATE_INVALID", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// -----------------------------------------------------------------------------
// /api/audit
// -----------------------------------------------------------------------------

func (h *handler) queryAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only GET is supported on /api/audit")
		return
	}
	q := r.URL.Query()
	tenantID := strings.TrimSpace(q.Get("tenant_id"))
	if tenantID == "" {
		// Fall back to the header for convenience.
		tenantID = tenantFromContext(r.Context())
	}
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "GOV_TENANT_REQUIRED",
			"tenant_id query param or X-Tenant-Id header is required")
		return
	}
	filter := audit.QueryFilter{TenantID: tenantID}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.To = &t
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			filter.Limit = n
		}
	}
	// action scopes to a single audit_log.action discriminator — the O+
	// egress-audit read (CHO-2245) passes action=external_egress.
	if v := strings.TrimSpace(q.Get("action")); v != "" {
		filter.Action = v
	}
	events, err := h.audits.Query(r.Context(), filter)
	if err != nil {
		log.Printf("audit query error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "audit query failed")
		return
	}
	writeJSON(w, http.StatusOK, listResponse{Items: events, Total: len(events)})
}

// -----------------------------------------------------------------------------
// /api/imda
// -----------------------------------------------------------------------------

type createAssessmentRequest struct {
	Dimension  string   `json:"dimension"`
	Score      int      `json:"score"`
	Indicators []string `json:"indicators,omitempty"`
}

func (h *handler) createAssessment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only POST is supported on /api/imda/assessments")
		return
	}
	var req createAssessmentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_BODY", err.Error())
		return
	}
	tenantID := tenantFromContext(r.Context())
	gcid := gcidFromContext(r.Context())
	a, err := imda.New(imda.NewParams{
		TenantID:     tenantID,
		Dimension:    imda.Dimension(req.Dimension),
		Score:        req.Score,
		Indicators:   req.Indicators,
		AssessorGcid: gcid,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_ASSESSMENT", err.Error())
		return
	}
	if err := h.imdas.Append(r.Context(), a); err != nil {
		log.Printf("imda append error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "failed to append assessment")
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (h *handler) imdaDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only GET is supported on /api/imda/dashboard")
		return
	}
	q := r.URL.Query()
	tenantID := strings.TrimSpace(q.Get("tenant_id"))
	if tenantID == "" {
		tenantID = tenantFromContext(r.Context())
	}
	dash, err := h.imdas.Dashboard(r.Context(), tenantID)
	if err != nil {
		log.Printf("imda dashboard error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "dashboard failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":  tenantID,
		"dimensions": dash,
	})
}

// -----------------------------------------------------------------------------
// /api/compliance/reports
// -----------------------------------------------------------------------------

func (h *handler) generateReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only POST is supported on /api/compliance/reports")
		return
	}
	tenantID := tenantFromContext(r.Context())
	report, err := h.gen.Generate(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "GOV_REPORT_INVALID", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, report)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errEmptyBody
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errEnvelope struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errEnvelope{Code: code, Message: msg})
}

// _ keeps context import used for tooling parity even when no helper uses it.
var _ = context.TODO
