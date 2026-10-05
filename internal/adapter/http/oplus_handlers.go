// oplus_handlers.go — O+ hydration HTTP endpoints (Phase B of the
// /Users/daleleung/.claude/plans/atomic-napping-spring.md hydration plan).
//
// Two endpoints added:
//
//	GET /api/hitl/pending
//	    Read-only list of HITL gates awaiting review. Queries
//	    hitl_decision_log via evidence.Repository.QueryHITLDecisions with a
//	    decision-status filter; pagination via ?limit + ?offset; tenant
//	    filter from the session (X-Tenant-Id middleware).
//
//	GET /api/imda/dimensions/{name}/rubric
//	    Rubric drilldown for one IMDA dimension. Delegates to the rubric
//	    resolver loaded from config/imda_rubric.yaml. {name} is canonicalised
//	    via imda.Canonicalise() so the deprecated v1 aliases (risk_levels /
//	    stakeholder_interaction / internal_governance / operations_management)
//	    are accepted alongside the ADR-141 canonical labels.
//
// Per [[feedback-no-stubs-real-wiring]] both handlers query the real
// evidence.Repository + rubric.Resolver — no in-memory stubs at the
// adapter layer. Wiring in cmd/server/main.go feeds the production
// repositories through.
package httpadapter

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
	usecaseimda "github.com/apollo-chora/chora-governance/internal/usecase/imda"
)

// AuditPublisher is the outbound port the HITL verdict handlers use to emit
// the governance audit event to the transactional outbox. The concrete
// implementation (outbox.Publisher) writes a pending outbox_events row that
// the Dispatcher drains to the event bus. Defining the port here (rather than
// importing the outbox package) keeps the adapter dependency direction clean
// and lets tests inject a recording fake.
type AuditPublisher interface {
	PublishWithError(topic string, h govevents.Header, payload map[string]interface{}) (govevents.PublishedEvent, error)
}

// oplusHandler holds the request-time deps for the O+ endpoints.
type oplusHandler struct {
	repo     evidence.Repository
	resolver *rubric.Resolver
	// audits is the append-only hash-chained audit log. HITL verdict
	// handlers (approve/reject) record an audit row before responding 200.
	audits audit.Repository
	// publisher emits the governance audit event to the outbox (optional —
	// nil ⇒ audit_log row still written, no Pub/Sub emission).
	publisher AuditPublisher
	// dashboardSvc is reserved for a future O+ endpoint that calls the
	// rubric-derived IMDA dashboard service directly (Phase C/D scope).
	// Kept on the struct so the wiring in handler.go + cmd/server/main.go
	// stays consistent during the multi-wave rollout.
	dashboardSvc *usecaseimda.Service //nolint:unused // wired for follow-up phase
}

// registerOPlusRoutes adds the O+ HTTP surface to mux:
//
//	GET  /api/hitl/pending
//	POST /api/hitl/decisions/{id}/claim
//	POST /api/hitl/decisions/{id}/release
//	POST /api/hitl/decisions/{id}/approve
//	POST /api/hitl/decisions/{id}/reject
//	GET  /api/imda/dimensions/{name}/rubric
//
// Called from NewRouter when OPlusDeps is populated.
func registerOPlusRoutes(mux *http.ServeMux, h *oplusHandler) {
	mux.HandleFunc("/api/hitl/pending", h.hitlPending)
	mux.HandleFunc("/api/hitl/decisions/", h.hitlDecisionRouter)
	mux.HandleFunc("/api/imda/dimensions/", h.dimensionRubricRouter)
}

// -----------------------------------------------------------------------------
// GET /api/hitl/pending
//
// Query params:
//
//	?limit=20        max records to return (default 20, cap 100)
//	?offset=0        offset for pagination
//	?status=pending  filter by HitlVerdict. Default "pending" — returns rows
//	                 where the operator has NOT yet recorded a final verdict.
//	                 Other accepted values: approve | reject | edit
//
// Returns:
//
//	{
//	  "items":  [ {decision_id, run_id, operator_gcid, decision, autonomy_level,
//	               edit_payload, lifecycle_stage, decided_at}, ... ],
//	  "total":  N,
//	  "limit":  20,
//	  "offset": 0
//	}
//
// HITL pending semantics: the canonical hitl_decision_log per Tier 3 is
// append-only and records the verdict at decision time. "pending" rows are
// HITL gates that have been raised but the operator hasn't yet decided —
// this corresponds to records authored with Decision="pending" (a
// non-canonical value the repository surfaces transparently when present;
// per the schema today this set may be empty until the broader HITL
// queue aggregate ships in a follow-up wave).
// -----------------------------------------------------------------------------

type hitlPendingResponse struct {
	Items  []hitlPendingItem `json:"items"`
	Total  int               `json:"total"`
	Limit  int               `json:"limit"`
	Offset int               `json:"offset"`
}

type hitlPendingItem struct {
	DecisionID   string `json:"decision_id"`
	RunID        string `json:"run_id"`
	OperatorGcid string `json:"operator_gcid,omitempty"`
	// AssigneeGcid is the reviewer GCID currently responsible for the gate.
	// NULL = unassigned (default at creation). Distinct from OperatorGcid
	// (which records who DECIDED, post-verdict). See HITLDecision godoc.
	// Set when a reviewer claims the gate via the (deferred to wave N+1)
	// POST /api/hitl/decisions/{id}/claim endpoint.
	AssigneeGcid   *string `json:"assignee_gcid"`
	Decision       string  `json:"decision"`
	AutonomyLevel  string  `json:"autonomy_level"`
	LifecycleStage string  `json:"lifecycle_stage"`
	DecidedAt      string  `json:"decided_at,omitempty"`
	// Note is the operator's optional verdict rationale (approve/reject).
	// Empty for pending/claimed rows. Sourced from edit_payload's reserved
	// note key by the evidence repository loaders.
	Note string `json:"note,omitempty"`
	// CHO-2368 P2 — the three keys the gateway's HITLPendingItem actually
	// reads, so a pending prompt-plan gate renders a meaningful O+ card
	// instead of a blank one. AgentID rides edit_payload (reserved key);
	// Summary mirrors Note (the gate-raise reason for pending rows);
	// CreatedAt is the gate-raised timestamp in RFC3339 (the FE waiting-since
	// otherwise renders zero-time).
	AgentID   string `json:"agent_id,omitempty"`
	Summary   string `json:"summary,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

func (h *oplusHandler) hitlPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "GET only")
		return
	}
	if h.repo == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_EVIDENCE_REPO_UNAVAILABLE",
			"evidence repository not wired")
		return
	}
	tenantID := tenantFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "GOV_TENANT_REQUIRED",
			"X-Tenant-Id header is required")
		return
	}
	q := r.URL.Query()
	limit := parseIntOrDefault(q.Get("limit"), 20)
	if limit > 100 {
		limit = 100
	}
	offset := parseIntOrDefault(q.Get("offset"), 0)
	statusFilter := strings.ToLower(strings.TrimSpace(q.Get("status")))
	if statusFilter == "" {
		statusFilter = "pending"
	}

	rows, err := h.repo.QueryHITLDecisions(r.Context(), evidence.QueryFilter{
		TenantID: tenantID,
		// Pull the broader window in-repo; we slice + filter below to keep
		// the query API stable while supporting the new status filter.
		Limit:  limit + offset + 200, // headroom for filter loss
		Offset: 0,
	})
	if err != nil {
		log.Printf("hitl pending query: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "hitl query failed")
		return
	}

	// Filter by status — pending = empty/literal "pending"; otherwise match
	// the canonical HitlVerdict values.
	filtered := make([]*evidence.HITLDecision, 0, len(rows))
	for _, d := range rows {
		if !statusMatchesHITL(statusFilter, d.Decision) {
			continue
		}
		filtered = append(filtered, d)
	}

	// Apply offset + limit slicing post-filter.
	total := len(filtered)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	page := filtered[start:end]

	items := make([]hitlPendingItem, 0, len(page))
	for _, d := range page {
		agentID, _ := d.EditPayload[evidence.AgentIDEditPayloadKey].(string)
		items = append(items, hitlPendingItem{
			DecisionID:     d.DecisionID,
			RunID:          d.RunID,
			OperatorGcid:   d.OperatorGcid,
			AssigneeGcid:   d.AssigneeGcid,
			Decision:       string(d.Decision),
			AutonomyLevel:  string(d.AutonomyLevel),
			LifecycleStage: string(d.LifecycleStage),
			DecidedAt:      d.DecidedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Note:           d.Note,
			AgentID:        agentID,
			Summary:        d.Note,
			CreatedAt:      d.DecidedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, hitlPendingResponse{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// statusMatchesHITL reports whether a status filter token matches a stored
// HitlVerdict. Canonical verdicts (approve / reject / edit) match exactly;
// "pending" matches either an empty Decision or the literal "pending"
// sentinel.
func statusMatchesHITL(filter string, decision evidence.HitlVerdict) bool {
	stored := strings.ToLower(strings.TrimSpace(string(decision)))
	switch filter {
	case "pending":
		return stored == "" || stored == "pending"
	case "approve", "reject", "edit":
		return stored == filter
	default:
		return stored == filter
	}
}

// -----------------------------------------------------------------------------
// GET /api/imda/dimensions/{name}/rubric
//
// Returns the resolver output for the named dimension. {name} is
// canonicalised via imda.Canonicalise() so v1 aliases work.
//
// Response shape:
//
//	{
//	  "dimension": "accountability",
//	  "items":     [ {id, ref, title, evidence_source, status,
//	                  evidence_source_url, derivation_mode}, ... ],
//	  "total":     N,
//	  "pass_rate": 0.0..1.0
//	}
// -----------------------------------------------------------------------------

type dimensionRubricResponse struct {
	Dimension string              `json:"dimension"`
	Items     []rubric.RubricItem `json:"items"`
	Total     int                 `json:"total"`
	PassRate  float64             `json:"pass_rate"`
}

// dimensionRubricRouter dispatches /api/imda/dimensions/{name}/rubric. Any
// other sub-path under /api/imda/dimensions/ is 404.
func (h *oplusHandler) dimensionRubricRouter(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/imda/dimensions/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) != 2 || parts[1] != "rubric" {
		writeError(w, http.StatusNotFound, "GOV_NOT_FOUND",
			"unknown dimensions sub-resource (expected /api/imda/dimensions/{name}/rubric)")
		return
	}
	name := strings.TrimSpace(parts[0])
	if name == "" {
		writeError(w, http.StatusBadRequest, "GOV_DIMENSION_REQUIRED",
			"dimension name is required in the path")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "GET only")
		return
	}
	if h.resolver == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_RUBRIC_UNAVAILABLE",
			"rubric resolver not wired")
		return
	}
	tenantID := tenantFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "GOV_TENANT_REQUIRED",
			"X-Tenant-Id header is required")
		return
	}
	// Canonicalise on input — accept v1 aliases.
	canonical := imda.Canonicalise(name)
	if !canonical.Valid() {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_DIMENSION",
			"dimension must be one of accountability|transparency|safety_and_robustness|fairness_and_human_oversight (or v1 alias)")
		return
	}
	items, err := h.resolver.Resolve(r.Context(), tenantID, string(canonical))
	if err != nil {
		writeError(w, http.StatusBadRequest, "GOV_RESOLVE_FAILED", err.Error())
		return
	}
	rate, err := h.resolver.PassRate(r.Context(), tenantID, string(canonical))
	if err != nil {
		log.Printf("oplus rubric pass-rate: %v", err)
		// fall through with 0 — items already populated
	}
	writeJSON(w, http.StatusOK, dimensionRubricResponse{
		Dimension: string(canonical),
		Items:     items,
		Total:     len(items),
		PassRate:  rate,
	})
}

// -----------------------------------------------------------------------------
// POST /api/hitl/decisions/{id}/claim
// POST /api/hitl/decisions/{id}/release
//
// Self-claim model (per migration 0008 + ADR-141 HITL lifecycle): a reviewer
// claims a pending HITL gate, setting assignee_gcid on the hitl_decision_log
// row. Distinct from operator_gcid which records who DECIDED post-verdict.
//
// Request body (JSON):
//
//	{ "operator_gcid": "<gcid>" }
//
// Tenant from X-Tenant-Id middleware. The handler:
//
//	1. Loads the row via repo.LoadHITLDecision (tenant-scoped — cross-tenant
//	   ⇒ 404 no-existence-leak).
//	2. Invokes domain Claim()/Release() — enforces blank-gcid rejection,
//	   already-claimed → ErrHITLAlreadyClaimed (409), wrong-assignee on
//	   release → ErrHITLNotAssignee (403), terminal verdict → ErrHITLTerminal
//	   (409).
//	3. Persists via repo.UpdateAssigneeGcid.
//	4. Returns 200 with the updated aggregate.
//
// HTTP status mapping (per N7 contract):
//
//	200 — claim/release succeeded
//	404 — decision not found OR cross-tenant (no existence leak)
//	409 — already claimed (claim) OR terminal verdict (claim/release)
//	403 — release attempted by non-assignee
//	422 — blank operator_gcid OR malformed JSON
//	503 — evidence repo not wired
//
// -----------------------------------------------------------------------------

type hitlClaimRequest struct {
	OperatorGcid string `json:"operator_gcid"`
	// Note is the operator's optional free-text rationale. Read on the
	// approve/reject actions; ignored (but tolerated) on claim/release.
	Note string `json:"note"`
}

// hitlDecisionRouter dispatches /api/hitl/decisions/{id}/{claim|release|approve|reject}.
func (h *oplusHandler) hitlDecisionRouter(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/hitl/decisions/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "GOV_NOT_FOUND",
			"unknown hitl decision sub-resource (expected /api/hitl/decisions/{id}/{claim|release|approve|reject})")
		return
	}
	decisionID := strings.TrimSpace(parts[0])
	action := strings.ToLower(strings.TrimSpace(parts[1]))
	if decisionID == "" {
		writeError(w, http.StatusBadRequest, "GOV_DECISION_ID_REQUIRED",
			"decision id is required in the path")
		return
	}
	switch action {
	case "claim":
		h.hitlClaim(w, r, decisionID)
	case "release":
		h.hitlRelease(w, r, decisionID)
	case "approve":
		h.hitlVerdict(w, r, decisionID, evidence.HitlApprove)
	case "reject":
		h.hitlVerdict(w, r, decisionID, evidence.HitlReject)
	default:
		writeError(w, http.StatusNotFound, "GOV_NOT_FOUND",
			"unknown action; expected claim, release, approve or reject")
	}
}

func (h *oplusHandler) hitlClaim(w http.ResponseWriter, r *http.Request, decisionID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "POST only")
		return
	}
	if h.repo == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_EVIDENCE_REPO_UNAVAILABLE",
			"evidence repository not wired")
		return
	}
	tenantID := tenantFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "GOV_TENANT_REQUIRED",
			"X-Tenant-Id header is required")
		return
	}
	operatorGcid, ok := decodeOperatorGcid(w, r)
	if !ok {
		return
	}
	d, err := h.repo.LoadHITLDecision(r.Context(), tenantID, decisionID)
	if err != nil {
		if errors.Is(err, evidence.ErrNotFound) {
			writeError(w, http.StatusNotFound, "GOV_HITL_NOT_FOUND",
				"hitl decision not found")
			return
		}
		log.Printf("hitl claim load: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "load failed")
		return
	}
	now := time.Now().UTC()
	if err := d.Claim(operatorGcid, now); err != nil {
		writeHITLDomainError(w, err)
		return
	}
	if err := h.repo.UpdateAssigneeGcid(r.Context(), tenantID, decisionID, d.AssigneeGcid, now); err != nil {
		log.Printf("hitl claim persist: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR",
			"persist failed")
		return
	}
	writeJSON(w, http.StatusOK, hitlDecisionViewFromDomain(d))
}

func (h *oplusHandler) hitlRelease(w http.ResponseWriter, r *http.Request, decisionID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "POST only")
		return
	}
	if h.repo == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_EVIDENCE_REPO_UNAVAILABLE",
			"evidence repository not wired")
		return
	}
	tenantID := tenantFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "GOV_TENANT_REQUIRED",
			"X-Tenant-Id header is required")
		return
	}
	operatorGcid, ok := decodeOperatorGcid(w, r)
	if !ok {
		return
	}
	d, err := h.repo.LoadHITLDecision(r.Context(), tenantID, decisionID)
	if err != nil {
		if errors.Is(err, evidence.ErrNotFound) {
			writeError(w, http.StatusNotFound, "GOV_HITL_NOT_FOUND",
				"hitl decision not found")
			return
		}
		log.Printf("hitl release load: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "load failed")
		return
	}
	now := time.Now().UTC()
	if err := d.Release(operatorGcid, now); err != nil {
		writeHITLDomainError(w, err)
		return
	}
	if err := h.repo.UpdateAssigneeGcid(r.Context(), tenantID, decisionID, nil, now); err != nil {
		log.Printf("hitl release persist: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR",
			"persist failed")
		return
	}
	writeJSON(w, http.StatusOK, hitlDecisionViewFromDomain(d))
}

// hitlVerdict handles POST /api/hitl/decisions/{id}/approve and /reject.
//
// Mirrors hitlClaim (load → domain method → persist → 200) but the verdict is
// recorded by APPENDING a new hitl_decision_log row (the verdict columns are
// append-only at the DB layer per migration 0009; only assignee_gcid is
// mutable in place). The flow:
//
//  1. Load the pending row via repo.LoadHITLDecision (tenant-scoped — cross-
//     tenant ⇒ 404, no existence leak).
//  2. Invoke domain Approve()/Reject() — blank-gcid ⇒ 422; already-decided
//     (terminal verdict) ⇒ ErrHITLTerminal (409).
//  3. Stamp a fresh EventID on the mutated aggregate so the append is a new
//     immutable ledger entry (the pending row's EventID is preserved).
//  4. Persist via repo.RecordHITLVerdict (append).
//  5. Append a hash-chained audit_log row (IMDA D1 accountability) + publish
//     the governance audit event to the outbox (best-effort — a publish
//     failure does NOT roll back the recorded verdict; it is logged).
//  6. Return 200 with hitlDecisionViewFromDomain(d).
//
// Request body: { "operator_gcid": "<gcid>", "note": "<optional>" }.
func (h *oplusHandler) hitlVerdict(w http.ResponseWriter, r *http.Request, decisionID string, verdict evidence.HitlVerdict) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED", "POST only")
		return
	}
	if h.repo == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_EVIDENCE_REPO_UNAVAILABLE",
			"evidence repository not wired")
		return
	}
	tenantID := tenantFromContext(r.Context())
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "GOV_TENANT_REQUIRED",
			"X-Tenant-Id header is required")
		return
	}
	operatorGcid, note, ok := decodeHITLBody(w, r)
	if !ok {
		return
	}
	d, err := h.repo.LoadHITLDecision(r.Context(), tenantID, decisionID)
	if err != nil {
		if errors.Is(err, evidence.ErrNotFound) {
			writeError(w, http.StatusNotFound, "GOV_HITL_NOT_FOUND",
				"hitl decision not found")
			return
		}
		log.Printf("hitl verdict load: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "load failed")
		return
	}
	now := time.Now().UTC()
	var verdictErr error
	switch verdict {
	case evidence.HitlApprove:
		verdictErr = d.Approve(operatorGcid, note, now)
	case evidence.HitlReject:
		verdictErr = d.Reject(operatorGcid, note, now)
	default:
		writeError(w, http.StatusBadRequest, "GOV_HITL_INVALID",
			"unsupported verdict")
		return
	}
	if verdictErr != nil {
		writeHITLDomainError(w, verdictErr)
		return
	}
	// Stamp a fresh event_id so RecordHITLVerdict appends a NEW immutable
	// row rather than colliding with the pending row's event_id. UUIDv7 keeps
	// the verdict row time-sortable after the pending row.
	d.EventID = newHITLEventID()
	if err := h.repo.RecordHITLVerdict(r.Context(), d); err != nil {
		log.Printf("hitl verdict persist: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "persist failed")
		return
	}
	h.auditHITLVerdict(r, d, operatorGcid)
	writeJSON(w, http.StatusOK, hitlDecisionViewFromDomain(d))
}

// auditHITLVerdict appends a hash-chained audit_log row for the verdict and
// publishes the governance audit event to the outbox. Audit append failures
// are logged but do not fail the request (the verdict is already durably
// recorded). Publish failures are likewise best-effort + logged.
func (h *oplusHandler) auditHITLVerdict(r *http.Request, d *evidence.HITLDecision, operatorGcid string) {
	action := "governance.hitl.decision_" + string(d.Decision)
	resource := "hitl_decision:" + d.DecisionID
	decision := audit.DecisionPermitted
	if d.Decision == evidence.HitlReject {
		decision = audit.DecisionDenied
	}
	if h.audits != nil {
		ev, err := audit.New(audit.NewParams{
			TenantID:    d.TenantID,
			Gcid:        operatorGcid,
			ActorGcid:   operatorGcid,
			Action:      action,
			Resource:    resource,
			Decision:    decision,
			Reason:      d.Note,
			SubjectType: "hitl_decision",
			SubjectID:   d.DecisionID,
			Traceparent: r.Header.Get("traceparent"),
			Tracestate:  r.Header.Get("tracestate"),
		})
		if err != nil {
			log.Printf("hitl verdict audit build: %v", err)
		} else if err := h.audits.Append(r.Context(), ev); err != nil {
			log.Printf("hitl verdict audit append: %v", err)
		}
	}
	h.publishHITLVerdictAudit(r, d, operatorGcid, action, resource)
}

// publishHITLVerdictAudit emits chora.governance.audit.recorded.v1 to the
// outbox (best-effort). No-op when no publisher is wired.
func (h *oplusHandler) publishHITLVerdictAudit(r *http.Request, d *evidence.HITLDecision, operatorGcid, action, resource string) {
	if h.publisher == nil {
		return
	}
	// AuditResult enum (chora.governance.v1): ALLOWED=1, DENIED=2.
	result := 1
	if d.Decision == evidence.HitlReject {
		result = 2
	}
	payload := map[string]interface{}{
		"audit_id":            d.EventID,
		"actor_gcid":          operatorGcid,
		"target_resource_uri": resource,
		"action":              action,
		"result":              result,
		"annotation":          d.Note,
		"occurred_at":         d.DecidedAt,
	}
	if _, err := h.publisher.PublishWithError(govevents.TopicAuditRecorded, govevents.Header{
		TenantID:    d.TenantID,
		GCID:        operatorGcid,
		Traceparent: r.Header.Get("traceparent"),
	}, payload); err != nil {
		// Fail-loud in logs but do not fail the request: the verdict + the
		// hash-chained audit_log row are already durable. The outbox is the
		// at-least-once delivery path; a transient enqueue error here is
		// recoverable only by re-emit, which a follow-up reconciliation
		// (deferred) would own.
		log.Printf("hitl verdict audit publish: topic=%s err=%v", govevents.TopicAuditRecorded, err)
	}
}

// newHITLEventID mints a UUIDv7 for a verdict row's event_id. Standalone to
// avoid coupling the http adapter to a specific uuid pkg version.
func newHITLEventID() string {
	const buflen = 16
	var b [buflen]byte
	now := uint64(time.Now().UnixMilli())
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)
	if _, err := rand.Read(b[6:]); err != nil {
		for i := 6; i < buflen; i++ {
			b[i] = byte(now >> uint(8*(i-6)))
		}
	}
	b[6] = (b[6] & 0x0F) | 0x70
	b[8] = (b[8] & 0x3F) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// decodeOperatorGcid parses the {operator_gcid:...} request body, writes the
// 422 error response on failure, and returns the trimmed value + an ok flag.
func decodeOperatorGcid(w http.ResponseWriter, r *http.Request) (string, bool) {
	op, _, ok := decodeHITLBody(w, r)
	return op, ok
}

// decodeHITLBody parses the {operator_gcid, note} request body. operator_gcid
// is required (blank ⇒ 422); note is optional. Writes the 422 error response
// on failure and returns the trimmed operator_gcid, the raw note, and an ok
// flag. Shared by claim/release (which ignore note) + approve/reject.
func decodeHITLBody(w http.ResponseWriter, r *http.Request) (operatorGcid, note string, ok bool) {
	var req hitlClaimRequest
	if r.Body == nil {
		writeError(w, http.StatusUnprocessableEntity, "GOV_INVALID_BODY",
			"operator_gcid is required")
		return "", "", false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			writeError(w, http.StatusUnprocessableEntity, "GOV_INVALID_BODY",
				"operator_gcid is required")
			return "", "", false
		}
		writeError(w, http.StatusUnprocessableEntity, "GOV_INVALID_BODY", err.Error())
		return "", "", false
	}
	trimmed := strings.TrimSpace(req.OperatorGcid)
	if trimmed == "" {
		writeError(w, http.StatusUnprocessableEntity, "GOV_OPERATOR_GCID_REQUIRED",
			"operator_gcid is required (blank string is not a valid GCID)")
		return "", "", false
	}
	return trimmed, req.Note, true
}

// writeHITLDomainError maps the evidence package's sentinel claim/release
// errors to HTTP status codes per the N7 contract. Non-sentinel errors fall
// through to 422 (unprocessable entity) — they represent domain validation
// failures (blank GCID, etc.) that are caller-fixable.
func writeHITLDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, evidence.ErrHITLAlreadyClaimed):
		writeError(w, http.StatusConflict, "GOV_HITL_ALREADY_CLAIMED",
			"hitl decision is already claimed by another reviewer")
	case errors.Is(err, evidence.ErrHITLNotAssignee):
		writeError(w, http.StatusForbidden, "GOV_HITL_NOT_ASSIGNEE",
			"only the current assignee may release this gate")
	case errors.Is(err, evidence.ErrHITLTerminal):
		writeError(w, http.StatusConflict, "GOV_HITL_TERMINAL",
			"hitl decision has a recorded verdict — claim/release are no longer valid")
	default:
		writeError(w, http.StatusUnprocessableEntity, "GOV_HITL_INVALID", err.Error())
	}
}

// hitlDecisionViewFromDomain projects the aggregate to the same response item
// shape as /api/hitl/pending so FE consumers can reuse the same parser on
// claim/release results.
func hitlDecisionViewFromDomain(d *evidence.HITLDecision) hitlPendingItem {
	return hitlPendingItem{
		DecisionID:     d.DecisionID,
		RunID:          d.RunID,
		OperatorGcid:   d.OperatorGcid,
		AssigneeGcid:   d.AssigneeGcid,
		Decision:       string(d.Decision),
		AutonomyLevel:  string(d.AutonomyLevel),
		LifecycleStage: string(d.LifecycleStage),
		DecidedAt:      d.DecidedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Note:           d.Note,
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func parseIntOrDefault(s string, fallback int) int {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}
