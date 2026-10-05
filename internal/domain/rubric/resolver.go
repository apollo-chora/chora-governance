// Package rubric resolves per-item IMDA rubric statuses for the O+ dimensions
// drilldown. Per Phase B of the O+ hydration plan (anchoring decision #3:
// hybrid static + auto derivation).
//
// Each rubric item carried by config/imda_rubric.yaml has a derivation_mode:
//
//   - static: status is passed through from static_status (subjective items
//     like RACI matrix presence, threat-model document existence; no event
//     stream exists to derive from)
//   - auto:   status is computed at request time by dispatching auto_query_key
//     into a function registry that queries the evidence repository
//     (counts evidence rows / pass-rate / threshold-based PASS/PARTIAL/FAIL)
//
// The resolver does NOT load the YAML — config loading is the caller's job
// (cmd/server/main.go reads the file via yaml.v3 and passes RubricConfig in).
// Keeping the YAML adapter outside the domain package preserves hexagonal
// dependency direction (domain has zero file/io imports).
//
// Per [[ai-observability-cloud-trace]] every chora.* attribute on
// agent_decision_log gets propagated to the projector → evidence row; the
// auto-mode functions tap that pipeline by counting rows in the per-
// dimension aggregates.
//
// Per [[feedback-no-stubs-real-wiring]] the resolver is wired to the same
// evidence.Repository the projector writes to — no in-memory stubs.
package rubric

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

// -----------------------------------------------------------------------------
// Public types — RubricItem (output) + RubricConfig (input from YAML)
// -----------------------------------------------------------------------------

// Status is the rubric status — PASS / PARTIAL / FAIL.
type Status string

const (
	// StatusPass — all evidence thresholds met.
	StatusPass Status = "PASS"
	// StatusPartial — some but not all evidence thresholds met.
	StatusPartial Status = "PARTIAL"
	// StatusFail — no evidence found or below thresholds.
	StatusFail Status = "FAIL"
)

// Valid reports whether s is one of the canonical statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusPass, StatusPartial, StatusFail:
		return true
	}
	return false
}

// Priority is the rubric item's remediation priority — P1 / P2 / P3.
//
// It drives the O+ dimensions traffic-light signal + the per-item badge:
//   - P1 = safety / security / legal / core-accountability — a single P1 FAIL
//     turns the dimension RED (attention).
//   - P2 = documentation / process / standard checks — TWO OR MORE P2 FAILs
//     turn the dimension AMBER (partial).
//   - P3 = nice-to-have — never affects the traffic light.
//
// Empty Priority is permitted (legacy / unscored items) — such items carry no
// badge and never affect the traffic-light rule.
type Priority string

const (
	// PriorityP1 — critical: a single FAIL turns the dimension RED.
	PriorityP1 Priority = "P1"
	// PriorityP2 — important: two or more FAILs turn the dimension AMBER.
	PriorityP2 Priority = "P2"
	// PriorityP3 — nice-to-have: never affects the traffic light.
	PriorityP3 Priority = "P3"
)

// Valid reports whether p is one of the canonical priorities (P1/P2/P3).
// The empty string is NOT valid here — callers treat empty as "unscored".
func (p Priority) Valid() bool {
	switch p {
	case PriorityP1, PriorityP2, PriorityP3:
		return true
	}
	return false
}

// DerivationMode is the rubric item's derivation strategy.
type DerivationMode string

const (
	// ModeAuto — computed at request time via a function registry call.
	ModeAuto DerivationMode = "auto"
	// ModeStatic — passed through from static_status in the YAML.
	ModeStatic DerivationMode = "static"
)

// Valid reports whether m is one of the canonical modes.
func (m DerivationMode) Valid() bool {
	switch m {
	case ModeAuto, ModeStatic:
		return true
	}
	return false
}

// ConfigItem mirrors a YAML rubric entry. Loaded by the caller; the resolver
// reads it via Resolve().
type ConfigItem struct {
	ID             string         `yaml:"id"`
	Ref            string         `yaml:"ref,omitempty"`
	Title          string         `yaml:"title"`
	EvidenceSource string         `yaml:"evidence_source"`
	DerivationMode DerivationMode `yaml:"derivation_mode"`
	StaticStatus   Status         `yaml:"static_status,omitempty"`
	AutoQueryKey   string         `yaml:"auto_query_key,omitempty"`
	Priority       Priority       `yaml:"priority,omitempty"`
	// EvidenceURL is an optional deep-link to the evidence backing this item
	// (e.g. a repo .md doc). For static items it surfaces directly as the FE
	// "View evidence ↗" link; for auto items it is a fallback when the
	// auto-fn returns no per-tenant evidence URL.
	EvidenceURL string `yaml:"evidence_url,omitempty"`
}

// DimensionConfig groups per-dimension rubric items.
type DimensionConfig struct {
	Items []ConfigItem `yaml:"items"`
}

// Config is the full parsed YAML payload.
type Config struct {
	Dimensions map[string]DimensionConfig `yaml:"dimensions"`
}

// RubricItem is the resolver's output — one row of the dimensions drilldown.
type RubricItem struct {
	ID                string   `json:"id"`
	Ref               string   `json:"ref,omitempty"`
	Title             string   `json:"title"`
	EvidenceSource    string   `json:"evidence_source"`
	Status            Status   `json:"status"`
	EvidenceSourceURL string   `json:"evidence_source_url,omitempty"`
	DerivationMode    string   `json:"derivation_mode"`
	Priority          Priority `json:"priority,omitempty"`
}

// -----------------------------------------------------------------------------
// AutoFunc — function registry contract for derivation_mode=auto items
// -----------------------------------------------------------------------------

// AutoFunc is the auto-query function shape. Receives the tenantID + the
// evidence.Repository the projector writes into; returns the per-item Status
// and the optional evidence_source_url for the FE "View ↗" deep-link.
//
// Implementations MUST NOT hold a long-running query — the resolver wraps a
// short per-request context.
type AutoFunc func(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error)

// -----------------------------------------------------------------------------
// Resolver — composes config + repo + auto-fn registry
// -----------------------------------------------------------------------------

// Resolver resolves rubric statuses by dimension. Wraps:
//
//   - cfg:   the loaded YAML config
//   - repo:  the evidence.Repository the projector writes to
//   - funcs: the function registry mapping auto_query_key → AutoFunc
//
// The default function registry (NewDefaultFuncRegistry) is populated with
// the 13 canonical auto_query_keys referenced from config/imda_rubric.yaml;
// callers can override via WithFuncRegistry for testing.
type Resolver struct {
	cfg   Config
	repo  evidence.Repository
	funcs map[string]AutoFunc
}

// NewResolver constructs a resolver from the supplied config + repo. Returns
// an error if the config is empty or the repo is nil.
//
// Per [[feedback-no-stubs-real-wiring]] repo MUST be the production
// evidence.Repository wired by cmd/server/main.go — NOT an in-memory stub.
func NewResolver(cfg Config, repo evidence.Repository) (*Resolver, error) {
	if len(cfg.Dimensions) == 0 {
		return nil, errors.New("rubric.NewResolver: config has no dimensions")
	}
	if repo == nil {
		return nil, errors.New("rubric.NewResolver: evidence repository is required")
	}
	return &Resolver{
		cfg:   cfg,
		repo:  repo,
		funcs: NewDefaultFuncRegistry(),
	}, nil
}

// WithFuncRegistry replaces the resolver's auto-fn registry. Test-only — the
// production registry is set by NewResolver and matches config/imda_rubric.yaml.
func (r *Resolver) WithFuncRegistry(funcs map[string]AutoFunc) *Resolver {
	r.funcs = funcs
	return r
}

// Dimensions returns the canonical dimension names that have config entries
// (sorted in ADR-141 order — accountability / transparency / safety_and_robustness
// / fairness_and_human_oversight).
func (r *Resolver) Dimensions() []string {
	out := make([]string, 0, len(imda.AllDimensions()))
	for _, d := range imda.AllDimensions() {
		if _, ok := r.cfg.Dimensions[string(d)]; ok {
			out = append(out, string(d))
		}
	}
	return out
}

// Resolve returns the per-item rubric statuses for one dimension. dimension
// is canonicalised via imda.Canonicalise() so deprecated v1 aliases are
// accepted. Returns an error if the dimension is unknown.
//
// auto-mode dispatch errors do NOT abort the whole resolve — the failing
// item gets Status=FAIL with the error swallowed (so one broken function
// can't take down the entire dimension drilldown). Errors are logged via
// log.Printf inside the caller scope.
func (r *Resolver) Resolve(ctx context.Context, tenantID, dimension string) ([]RubricItem, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("rubric.Resolve: tenant_id is required")
	}
	canonical := imda.Canonicalise(dimension)
	if !canonical.Valid() {
		return nil, fmt.Errorf("rubric.Resolve: unknown dimension %q", dimension)
	}
	cfg, ok := r.cfg.Dimensions[string(canonical)]
	if !ok {
		return nil, fmt.Errorf("rubric.Resolve: no config entries for dimension %q", canonical)
	}
	out := make([]RubricItem, 0, len(cfg.Items))
	for _, item := range cfg.Items {
		out = append(out, r.resolveItem(ctx, tenantID, item))
	}
	return out, nil
}

// ResolveAll returns all dimensions in one call — for callers that need
// the entire rubric drilldown (e.g. /api/imda/dashboard with full rubric).
func (r *Resolver) ResolveAll(ctx context.Context, tenantID string) (map[string][]RubricItem, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("rubric.ResolveAll: tenant_id is required")
	}
	out := make(map[string][]RubricItem, len(r.cfg.Dimensions))
	for _, d := range imda.AllDimensions() {
		cfg, ok := r.cfg.Dimensions[string(d)]
		if !ok {
			continue
		}
		items := make([]RubricItem, 0, len(cfg.Items))
		for _, item := range cfg.Items {
			items = append(items, r.resolveItem(ctx, tenantID, item))
		}
		out[string(d)] = items
	}
	return out, nil
}

// PassRate returns the fraction of PASS items in the dimension as a float in
// [0,1]. PARTIAL counts as 0.5; FAIL counts as 0. Used by usecase/imda/
// dashboard.go to derive D1-D4 percentages from real evidence × rubric.
//
// Returns (0, nil) when the dimension has no config entries (defensive — the
// dashboard usecase treats that as "no data" rather than 100%).
func (r *Resolver) PassRate(ctx context.Context, tenantID, dimension string) (float64, error) {
	items, err := r.Resolve(ctx, tenantID, dimension)
	if err != nil {
		return 0, err
	}
	if len(items) == 0 {
		return 0, nil
	}
	var total float64
	for _, it := range items {
		switch it.Status {
		case StatusPass:
			total += 1.0
		case StatusPartial:
			total += 0.5
		}
	}
	return total / float64(len(items)), nil
}

// resolveItem resolves a single rubric item to a RubricItem with status set.
// Static items pass through; auto items dispatch to the function registry.
//
// On any error path the returned RubricItem still carries the metadata
// (id/title/source) — only the status falls back to FAIL.
func (r *Resolver) resolveItem(ctx context.Context, tenantID string, item ConfigItem) RubricItem {
	out := RubricItem{
		ID:             item.ID,
		Ref:            item.Ref,
		Title:          item.Title,
		EvidenceSource: item.EvidenceSource,
		DerivationMode: string(item.DerivationMode),
		Priority:       item.Priority,
	}
	switch item.DerivationMode {
	case ModeStatic:
		// Static items surface their configured evidence deep-link directly.
		out.EvidenceSourceURL = item.EvidenceURL
		if !item.StaticStatus.Valid() {
			out.Status = StatusFail
			return out
		}
		out.Status = item.StaticStatus
		return out
	case ModeAuto:
		fn, ok := r.funcs[item.AutoQueryKey]
		if !ok {
			// Unknown auto key — fail closed; the deployment is misconfigured.
			out.Status = StatusFail
			return out
		}
		s, url, err := fn(ctx, tenantID, r.repo)
		if err != nil || !s.Valid() {
			out.Status = StatusFail
			return out
		}
		out.Status = s
		// Prefer the per-tenant evidence URL the auto-fn derived; fall back to
		// the item's configured static deep-link when the fn returns none.
		if strings.TrimSpace(url) != "" {
			out.EvidenceSourceURL = url
		} else {
			out.EvidenceSourceURL = item.EvidenceURL
		}
		return out
	default:
		out.Status = StatusFail
		return out
	}
}

// -----------------------------------------------------------------------------
// Default function registry — wired to evidence.Repository row counts
// -----------------------------------------------------------------------------

// thresholdsPctPass + thresholdsPctPartial are the canonical thresholds for
// the auto-mode functions (per anchoring decision #3 hybrid: auto items use a
// threshold derived from evidence row count / pass-rate).
//
// The PARTIAL band is intentionally wide so the dashboard surfaces transition
// states honestly (a single eval run shouldn't flip a rubric from FAIL to
// PASS — it should report PARTIAL until coverage is sustained).
const (
	thresholdPctPass    = 80.0
	thresholdPctPartial = 30.0
)

// auditWindowDays is the rolling lookback window for the auto-mode counters.
// 7d matches the canonical "is anyone actively using this?" question.
const auditWindowDays = 7

// NewDefaultFuncRegistry returns the canonical registry mapping the
// auto_query_keys referenced from config/imda_rubric.yaml. Each function
// counts the relevant evidence aggregate over the last 7d (window per
// auditWindowDays) and returns PASS / PARTIAL / FAIL via threshold check.
//
// The functions intentionally return FAIL when the underlying query fails —
// so dashboard hydration degrades gracefully (a transient DB blip during
// the 30s poll shows FAIL, not a 500 to the FE).
func NewDefaultFuncRegistry() map[string]AutoFunc {
	return map[string]AutoFunc{
		// D1 accountability auto items
		"audit_trail_coverage":    autoFromAccountability,
		"cost_tracking":           autoFromAccountabilityWithDecisionType("cost_recorded"),
		"data_lineage":            autoFromAccountabilityWithDecisionType("data_lineage"),
		"data_quality_validation": autoFromPolicyViolations,

		// D2 transparency auto items
		"explainability_reasoning": autoFromDecisionExplanations,
		"source_attribution":       autoFromDecisionExplanationsAudience(evidence.AudienceLearner),
		"model_version_tracking":   autoFromModelCards,

		// D3 safety_and_robustness auto items
		"content_safety_pipeline": autoFromPolicyViolations,
		"io_guardrails":           autoFromPolicyViolationsBySeverity("low"),
		"adversarial_testing":     autoFromRedTeamRuns,
		"quality_evaluation":      autoFromEvalRuns,
		"regression_detection":    autoFromEvalRunsRegressed,
		"circuit_breaker":         autoFromCircuitBreaker,

		// D4 fairness_and_human_oversight auto items
		"bias_testing":             autoFromBiasTestRuns,
		"hitl_approval_gates":      autoFromHITLDecisions,
		"demographic_bias_testing": autoFromBiasTestRunsByAttribute("demographic"),
	}
}

// rangeFilter returns an evidence.QueryFilter scoped to (tenant, last-7d).
func rangeFilter(tenantID string) evidence.QueryFilter {
	now := time.Now().UTC()
	from := now.Add(-time.Duration(auditWindowDays) * 24 * time.Hour)
	return evidence.QueryFilter{
		TenantID: tenantID,
		From:     &from,
		To:       &now,
	}
}

// countToStatus maps a row count to a Status via fixed thresholds.
//
//	count == 0              → FAIL
//	count >= passThreshold  → PASS
//	otherwise               → PARTIAL
func countToStatus(count, passThreshold int) Status {
	if count == 0 {
		return StatusFail
	}
	if count >= passThreshold {
		return StatusPass
	}
	return StatusPartial
}

// passRateToStatus maps a 0..1 pass-rate to a Status via percentage thresholds.
func passRateToStatus(passRate float64) Status {
	pct := passRate * 100.0
	switch {
	case pct >= thresholdPctPass:
		return StatusPass
	case pct >= thresholdPctPartial:
		return StatusPartial
	default:
		return StatusFail
	}
}

// -----------------------------------------------------------------------------
// Auto-fn implementations
// -----------------------------------------------------------------------------

// autoFromAccountability — D1 audit_trail_coverage / cost_tracking / data_lineage.
// PASS when there are >= 10 accountability evidence rows in the last 7d; PARTIAL
// when >= 1; FAIL when none. The 10-row threshold is the canonical "any sustained
// audit activity" bar; the FE shows the exact count in the drilldown.
func autoFromAccountability(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryAccountability(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	return countToStatus(len(rows), 10), "", nil
}

// autoFromAccountabilityWithDecisionType narrows the D1 count to rows whose
// DecisionType matches the supplied filter. Used for cost_tracking (counts
// only "cost_recorded" decisions) + data_lineage (counts only "data_lineage"
// decisions). When no rows match, drops to FAIL.
func autoFromAccountabilityWithDecisionType(decisionType string) AutoFunc {
	return func(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
		rows, err := repo.QueryAccountability(ctx, rangeFilter(tenantID))
		if err != nil {
			return StatusFail, "", err
		}
		matched := 0
		for _, row := range rows {
			if row.DecisionType == decisionType {
				matched++
			}
		}
		return countToStatus(matched, 5), "", nil
	}
}

// autoFromPolicyViolations — D1 data_quality_validation / D3 content_safety_pipeline.
// Counts policy violations: PASS when 0 (clean run); PARTIAL when 1-5 (some
// blocks but bounded); FAIL when > 5 (rule churn).
//
// Inverted from row-count semantics — zero violations is good, many violations
// is bad. We invert by emitting PASS for low counts.
func autoFromPolicyViolations(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryPolicyViolations(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	count := len(rows)
	switch {
	case count == 0:
		return StatusPass, "", nil
	case count <= 5:
		return StatusPartial, "", nil
	default:
		return StatusFail, "", nil
	}
}

// autoFromPolicyViolationsBySeverity narrows to a single severity bucket.
// PASS when zero rows at the requested severity in the last 7d.
func autoFromPolicyViolationsBySeverity(severity string) AutoFunc {
	return func(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
		rows, err := repo.QueryPolicyViolations(ctx, rangeFilter(tenantID))
		if err != nil {
			return StatusFail, "", err
		}
		matched := 0
		for _, row := range rows {
			if strings.EqualFold(row.Severity, severity) {
				matched++
			}
		}
		switch {
		case matched == 0:
			return StatusPass, "", nil
		case matched <= 5:
			return StatusPartial, "", nil
		default:
			return StatusFail, "", nil
		}
	}
}

// autoFromDecisionExplanations — D2 explainability_reasoning.
// Counts decision_explanation rows; PASS when >= 10, PARTIAL when >= 1.
func autoFromDecisionExplanations(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryDecisionExplanation(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	return countToStatus(len(rows), 10), "", nil
}

// autoFromDecisionExplanationsAudience narrows to a single audience.
func autoFromDecisionExplanationsAudience(audience evidence.Audience) AutoFunc {
	return func(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
		f := rangeFilter(tenantID)
		f.Audience = audience
		rows, err := repo.QueryDecisionExplanation(ctx, f)
		if err != nil {
			return StatusFail, "", err
		}
		return countToStatus(len(rows), 5), "", nil
	}
}

// autoFromModelCards — D2 model_version_tracking. PASS when >= 1 model card
// registered in the lookback window; FAIL otherwise (no tracking).
func autoFromModelCards(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryModelCards(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	switch {
	case len(rows) >= 3:
		return StatusPass, "", nil
	case len(rows) >= 1:
		return StatusPartial, "", nil
	default:
		return StatusFail, "", nil
	}
}

// autoFromRedTeamRuns — D3 adversarial_testing. Pass-rate over the rolling
// window; PASS when verdict=="pass" rate >= 80%, PARTIAL when >= 30%.
func autoFromRedTeamRuns(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryRedTeamRuns(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	if len(rows) == 0 {
		return StatusFail, "", nil
	}
	pass := 0
	for _, r := range rows {
		if strings.EqualFold(r.Verdict, "pass") {
			pass++
		}
	}
	rate := float64(pass) / float64(len(rows))
	return passRateToStatus(rate), "", nil
}

// autoFromEvalRuns — D3 quality_evaluation. Pass-rate from non-regressed runs.
func autoFromEvalRuns(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryEvalRuns(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	if len(rows) == 0 {
		return StatusFail, "", nil
	}
	pass := 0
	for _, r := range rows {
		if !r.Regressed {
			pass++
		}
	}
	rate := float64(pass) / float64(len(rows))
	return passRateToStatus(rate), "", nil
}

// autoFromEvalRunsRegressed — D3 regression_detection. Inverted: PASS when
// regressions are rare; FAIL when they dominate.
func autoFromEvalRunsRegressed(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryEvalRuns(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	if len(rows) == 0 {
		// No eval runs at all → no regression detection coverage → FAIL.
		return StatusFail, "", nil
	}
	regressed := 0
	for _, r := range rows {
		if r.Regressed {
			regressed++
		}
	}
	rate := float64(len(rows)-regressed) / float64(len(rows))
	return passRateToStatus(rate), "", nil
}

// autoFromCircuitBreaker — D3 circuit_breaker. PASS when no breakers are open;
// PARTIAL when at least one half-open; FAIL when any open.
func autoFromCircuitBreaker(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryCircuitBreakers(ctx, evidence.QueryFilter{TenantID: tenantID})
	if err != nil {
		return StatusFail, "", err
	}
	if len(rows) == 0 {
		// No breakers configured — PASS by default (nothing is broken).
		return StatusPass, "", nil
	}
	for _, r := range rows {
		if r.State() == evidence.CircuitOpen {
			return StatusFail, "", nil
		}
	}
	for _, r := range rows {
		if r.State() == evidence.CircuitHalfOpen {
			return StatusPartial, "", nil
		}
	}
	return StatusPass, "", nil
}

// autoFromBiasTestRuns — D4 bias_testing. Pass-rate over the rolling window.
func autoFromBiasTestRuns(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryBiasTestRuns(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	if len(rows) == 0 {
		return StatusFail, "", nil
	}
	pass := 0
	for _, r := range rows {
		if r.Passed {
			pass++
		}
	}
	rate := float64(pass) / float64(len(rows))
	return passRateToStatus(rate), "", nil
}

// autoFromBiasTestRunsByAttribute narrows to a single ProtectedAttribute.
func autoFromBiasTestRunsByAttribute(attr string) AutoFunc {
	return func(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
		rows, err := repo.QueryBiasTestRuns(ctx, rangeFilter(tenantID))
		if err != nil {
			return StatusFail, "", err
		}
		matching := 0
		pass := 0
		for _, r := range rows {
			if !strings.EqualFold(r.ProtectedAttribute, attr) {
				continue
			}
			matching++
			if r.Passed {
				pass++
			}
		}
		if matching == 0 {
			return StatusFail, "", nil
		}
		rate := float64(pass) / float64(matching)
		return passRateToStatus(rate), "", nil
	}
}

// autoFromHITLDecisions — D4 hitl_approval_gates. PASS when >= 5 HITL decisions
// recorded in the lookback window (sustained operator activity), PARTIAL when
// >= 1, FAIL when 0.
func autoFromHITLDecisions(ctx context.Context, tenantID string, repo evidence.Repository) (Status, string, error) {
	rows, err := repo.QueryHITLDecisions(ctx, rangeFilter(tenantID))
	if err != nil {
		return StatusFail, "", err
	}
	return countToStatus(len(rows), 5), "", nil
}
