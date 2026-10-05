// Package httpadapter — IMDA D1-D4 evidence read API + Three-Audience
// explanation API + evidence-pack ZIP export endpoint.
//
// Per audit-platform-fillgaps.md §5 (R-PLAT-2 + Wave 5 dispatch), this
// extends the chora-governance REST surface with the production-grade
// O+ data read API and replaces the prior mock evidence-pack export.
//
// New endpoints:
//
//	GET  /v1/governance/dimensions/d1/accountability — D1 evidence
//	GET  /v1/governance/dimensions/d2/transparency   — D2 model+data cards + explanations
//	GET  /v1/governance/dimensions/d3/safety         — D3 red-team/eval/cost/breaker/quarantine/policy
//	GET  /v1/governance/dimensions/d4/fairness       — D4 bias + HITL
//	GET  /v1/governance/decisions/{id}/explanation   — Three-Audience explanation (audience= ?)
//	GET  /v1/governance/audit/verify                 — hash-chain end-to-end verify
//	POST /v1/governance/evidence/export              — ZIP pack
//
// Authentication: tenant + gcid still required via headers (per existing
// tenantContext middleware). Auditor-only endpoints inspect the role grant
// from the X-Chora-Role header (M14 will replace this with Identity Platform
// claims; for now we accept the header from the BFF gateway).
package httpadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/evidencepack"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// IMDADeps wires the imda handlers (extends Deps in handler.go).
type IMDADeps struct {
	EvidenceRepo evidence.Repository
	Projector    *projector.Projector
	Exporter     *evidencepack.Exporter
}

type imdaHandler struct {
	repo   evidence.Repository
	proj   *projector.Projector
	exp    *evidencepack.Exporter
	audits audit.Repository
}

// registerIMDARoutes adds the production IMDA D1-D4 routes to mux.
func registerIMDARoutes(mux *http.ServeMux, h *imdaHandler) {
	mux.HandleFunc("/v1/governance/dimensions/d1/accountability", h.dimensionD1)
	mux.HandleFunc("/v1/governance/dimensions/d2/transparency", h.dimensionD2)
	mux.HandleFunc("/v1/governance/dimensions/d3/safety", h.dimensionD3)
	mux.HandleFunc("/v1/governance/dimensions/d4/fairness", h.dimensionD4)
	mux.HandleFunc("/v1/governance/decisions/", h.decisionsRouter)
	mux.HandleFunc("/v1/governance/audit/verify", h.auditVerify)
	mux.HandleFunc("/v1/governance/evidence/export", h.evidenceExport)

	// Convenience: synchronous projector entry for testing + integration.
	// Production publishers use Pub/Sub subscribers wired in cmd/server/main.go.
	mux.HandleFunc("/v1/governance/evidence/project", h.evidenceProject)
}

// -----------------------------------------------------------------------------
// D1
// -----------------------------------------------------------------------------

func (h *imdaHandler) dimensionD1(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "GET only")
		return
	}
	if !roleHasAccess(r, AudienceAuditor, AudienceInstructorAdmin) {
		writeError(w, http.StatusForbidden, "GOV_FORBIDDEN", "auditor or instructor_admin role required")
		return
	}
	filter := buildEvidenceFilter(r, tenantFromContext(r.Context()))
	rows, err := h.repo.QueryAccountability(r.Context(), filter)
	if err != nil {
		log.Printf("D1 query error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "query failed")
		return
	}
	writeJSON(w, http.StatusOK, listResponse{Items: rows, Total: len(rows)})
}

// -----------------------------------------------------------------------------
// D2
// -----------------------------------------------------------------------------

func (h *imdaHandler) dimensionD2(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "GET only")
		return
	}
	if !roleHasAccess(r, AudienceAuditor, AudienceInstructorAdmin, AudienceLearner) {
		writeError(w, http.StatusForbidden, "GOV_FORBIDDEN", "role required")
		return
	}
	filter := buildEvidenceFilter(r, tenantFromContext(r.Context()))
	mcs, err := h.repo.QueryModelCards(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "model cards query failed")
		return
	}
	dcs, err := h.repo.QueryDataCards(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "data cards query failed")
		return
	}
	// Decision explanation — role-filtered via audienceCanSee equivalent.
	expFilter := filter
	expFilter.Audience = roleAudience(r)
	exps, err := h.repo.QueryDecisionExplanation(r.Context(), expFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "explanations query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"model_cards":           mcs,
		"data_cards":            dcs,
		"decision_explanations": exps,
	})
}

// -----------------------------------------------------------------------------
// D3
// -----------------------------------------------------------------------------

func (h *imdaHandler) dimensionD3(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "GET only")
		return
	}
	if !roleHasAccess(r, AudienceAuditor, AudienceInstructorAdmin) {
		writeError(w, http.StatusForbidden, "GOV_FORBIDDEN", "auditor or instructor_admin role required")
		return
	}
	tenantID := tenantFromContext(r.Context())
	filter := buildEvidenceFilter(r, tenantID)

	rts, _ := h.repo.QueryRedTeamRuns(r.Context(), filter)
	evs, _ := h.repo.QueryEvalRuns(r.Context(), filter)
	cas, _ := h.repo.QueryCostAnomalies(r.Context(), filter)
	pvs, _ := h.repo.QueryPolicyViolations(r.Context(), filter)
	cbs, _ := h.repo.QueryCircuitBreakers(r.Context(), evidence.QueryFilter{TenantID: tenantID})
	qs, _ := h.repo.QueryQuarantines(r.Context(), evidence.QueryFilter{TenantID: tenantID})

	writeJSON(w, http.StatusOK, map[string]any{
		"red_team_runs":         rts,
		"eval_runs":             evs,
		"cost_anomalies":        cas,
		"policy_violations":     pvs,
		"circuit_breaker_state": cbs,
		"quarantine_state":      qs,
	})
}

// -----------------------------------------------------------------------------
// D4
// -----------------------------------------------------------------------------

func (h *imdaHandler) dimensionD4(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "GET only")
		return
	}
	if !roleHasAccess(r, AudienceAuditor) {
		// HITL log is auditor-only by default per ADR-141 sensitivity.
		writeError(w, http.StatusForbidden, "GOV_FORBIDDEN", "auditor role required")
		return
	}
	filter := buildEvidenceFilter(r, tenantFromContext(r.Context()))
	bts, _ := h.repo.QueryBiasTestRuns(r.Context(), filter)
	hds, _ := h.repo.QueryHITLDecisions(r.Context(), filter)
	writeJSON(w, http.StatusOK, map[string]any{
		"bias_test_runs":    bts,
		"hitl_decision_log": hds,
	})
}

// -----------------------------------------------------------------------------
// /v1/governance/decisions/{id}/explanation — Three-Audience
// -----------------------------------------------------------------------------

func (h *imdaHandler) decisionsRouter(w http.ResponseWriter, r *http.Request) {
	const prefix = "/v1/governance/decisions/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) != 2 || parts[1] != "explanation" {
		writeError(w, http.StatusNotFound, "GOV_NOT_FOUND", "unknown decisions sub-resource")
		return
	}
	decisionID := parts[0]
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "GET only")
		return
	}
	tenantID := tenantFromContext(r.Context())
	audience := evidence.Audience(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("audience"))))
	if audience == "" {
		// Default to viewer's role.
		audience = roleAudience(r)
	}
	if !audience.Valid() {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_AUDIENCE",
			"audience must be one of learner|instructor_admin|auditor")
		return
	}
	// Role enforcement: viewer cannot request a higher-privileged audience.
	if !canViewAudience(roleAudience(r), audience) {
		writeError(w, http.StatusForbidden, "GOV_FORBIDDEN",
			"role cannot view requested audience")
		return
	}
	rows, err := h.repo.GetDecisionExplanationByDecisionID(r.Context(), tenantID, decisionID, audience)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision_id":  decisionID,
		"audience":     string(audience),
		"explanations": rows,
		"total":        len(rows),
	})
}

// -----------------------------------------------------------------------------
// /v1/governance/audit/verify
// -----------------------------------------------------------------------------

func (h *imdaHandler) auditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "GET only")
		return
	}
	if !roleHasAccess(r, AudienceAuditor) {
		writeError(w, http.StatusForbidden, "GOV_FORBIDDEN", "auditor role required")
		return
	}
	tenantID := tenantFromContext(r.Context())
	if h.audits == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_AUDIT_UNAVAILABLE", "audit repo not wired")
		return
	}
	result, err := h.audits.VerifyChain(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "verify failed")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// -----------------------------------------------------------------------------
// /v1/governance/evidence/export — REAL ZIP
// -----------------------------------------------------------------------------

type evidenceExportRequest struct {
	From       string   `json:"from,omitempty"`       // RFC3339
	To         string   `json:"to,omitempty"`         // RFC3339
	Dimensions []string `json:"dimensions,omitempty"` // empty = all
}

func (h *imdaHandler) evidenceExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "POST only")
		return
	}
	if !roleHasAccess(r, AudienceAuditor) {
		writeError(w, http.StatusForbidden, "GOV_FORBIDDEN", "auditor role required")
		return
	}
	if h.exp == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_EXPORTER_UNAVAILABLE",
			"evidence pack exporter not configured")
		return
	}
	var req evidenceExportRequest
	if err := decodeJSON(r, &req); err != nil && !errors.Is(err, errEmptyBody) {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_BODY", err.Error())
		return
	}
	tenantID := tenantFromContext(r.Context())
	expReq := evidencepack.ExportRequest{
		TenantID:   tenantID,
		Dimensions: req.Dimensions,
	}
	if req.From != "" {
		t, err := time.Parse(time.RFC3339, req.From)
		if err != nil {
			writeError(w, http.StatusBadRequest, "GOV_INVALID_FROM", "from must be RFC3339")
			return
		}
		expReq.From = t
	}
	if req.To != "" {
		t, err := time.Parse(time.RFC3339, req.To)
		if err != nil {
			writeError(w, http.StatusBadRequest, "GOV_INVALID_TO", "to must be RFC3339")
			return
		}
		expReq.To = t
	}
	out, err := h.exp.Export(r.Context(), expReq)
	if err != nil {
		writeError(w, http.StatusBadRequest, "GOV_EXPORT_FAILED", err.Error())
		return
	}

	// Stream the ZIP back. In production a Cloud Run Job writes to GCS and
	// returns a signed URL; the synchronous body is the M13.C Wave-5 path.
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=imda-evidence-pack-%s.zip", out.PackID))
	w.Header().Set("X-Pack-ID", out.PackID)
	w.Header().Set("X-Manifest-SHA256", out.ManifestSHA)
	w.Header().Set("X-Tenant-Id", out.TenantID)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.ZIPBytes)
}

// -----------------------------------------------------------------------------
// /v1/governance/evidence/project — synchronous projector entry for tests
// -----------------------------------------------------------------------------

func (h *imdaHandler) evidenceProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "POST only")
		return
	}
	if !roleHasAccess(r, AudienceAuditor) {
		writeError(w, http.StatusForbidden, "GOV_FORBIDDEN", "auditor role required")
		return
	}
	if h.proj == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_PROJECTOR_UNAVAILABLE",
			"projector not configured")
		return
	}
	var ev projector.IncomingEvent
	if err := decodeJSON(r, &ev); err != nil {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_BODY", err.Error())
		return
	}
	// Fill from context if caller omitted them.
	if ev.TenantID == "" {
		ev.TenantID = tenantFromContext(r.Context())
	}
	if ev.EventID == "" {
		writeError(w, http.StatusBadRequest, "GOV_EVENT_ID_REQUIRED", "event_id is required")
		return
	}
	if err := h.proj.Project(r.Context(), ev); err != nil {
		writeError(w, http.StatusBadRequest, "GOV_PROJECT_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":   "projected",
		"event_id": ev.EventID,
	})
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// AudienceLearner / InstructorAdmin / Auditor mirror evidence package
// constants for use in the role-grant header.
const (
	AudienceLearner         = "learner"
	AudienceInstructorAdmin = "instructor_admin"
	AudienceAuditor         = "auditor"

	headerRole = "X-Chora-Role"
)

// roleAudience extracts the viewer's role from the X-Chora-Role header.
// Defaults to learner (least privilege) when absent or invalid.
func roleAudience(r *http.Request) evidence.Audience {
	v := strings.ToLower(strings.TrimSpace(r.Header.Get(headerRole)))
	a := evidence.Audience(v)
	if a.Valid() {
		return a
	}
	return evidence.AudienceLearner
}

// roleHasAccess reports whether the request's role is in the allowed set.
func roleHasAccess(r *http.Request, allowed ...string) bool {
	role := string(roleAudience(r))
	for _, a := range allowed {
		if role == a {
			return true
		}
	}
	return false
}

// canViewAudience implements the Three-Audience visibility ladder:
//
//	learner          → can view learner only
//	instructor_admin → can view instructor_admin + learner
//	auditor          → can view all
func canViewAudience(viewer, target evidence.Audience) bool {
	switch viewer {
	case evidence.AudienceLearner:
		return target == evidence.AudienceLearner
	case evidence.AudienceInstructorAdmin:
		return target == evidence.AudienceInstructorAdmin || target == evidence.AudienceLearner
	case evidence.AudienceAuditor:
		return true
	}
	return false
}

// buildEvidenceFilter parses common query params (lifecycle, agent_id, from,
// to, limit, offset) into an evidence.QueryFilter scoped to tenantID.
func buildEvidenceFilter(r *http.Request, tenantID string) evidence.QueryFilter {
	q := r.URL.Query()
	f := evidence.QueryFilter{TenantID: tenantID}
	if v := strings.TrimSpace(q.Get("lifecycle_stage")); v != "" {
		f.LifecycleStage = evidence.LifecycleStage(strings.ToLower(v))
	}
	if v := strings.TrimSpace(q.Get("agent_id")); v != "" {
		f.AgentID = v
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			f.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			f.Offset = n
		}
	}
	return f
}

// errEmptyBody is the sentinel returned by decodeJSON for an empty body.
// Used to distinguish optional-body endpoints (export accepts no body) from
// invalid JSON.
var errEmptyBody = errors.New("empty body")

// decodeJSONOptional accepts an empty body without erroring.
func decodeJSONOptional(r *http.Request, v any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

var _ = decodeJSONOptional // keep helper available even if not yet used externally
