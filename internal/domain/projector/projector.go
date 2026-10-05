// Package projector routes IMDA dimension-tagged events into the right
// D1-D4 evidence aggregate. Subscribed to event bus topics from S2-S6 services
// per CLAUDE.md §6 ("OTLP everywhere", "trace context across event bus").
//
// Routing strategy:
//
//	chora_imda_dimension=accountability                → D1 accountability_evidence
//	chora_imda_dimension=transparency
//	  + EventType contains "model_card"               → D2 model_card_registry
//	  + EventType contains "data_card"                → D2 data_card_registry
//	  + otherwise (decision/explanation events)       → D2 decision_explanation
//	chora_imda_dimension=safety_and_robustness
//	  + EventType contains "red_team"                  → D3 red_team_runs
//	  + EventType contains "eval"                      → D3 eval_runs
//	  + EventType contains "cost_anomaly"              → D3 cost_anomalies
//	  + EventType contains "policy_violation"          → policy_violation_log
//	  + EventType contains "circuit_breaker"           → D3 circuit_breaker_state
//	  + EventType contains "quarantine"                → D3 quarantine_state
//	chora_imda_dimension=fairness_and_human_oversight
//	  + EventType contains "bias"                      → D4 bias_test_runs
//	  + EventType contains "hitl"                      → D4 hitl_decision_log
//
// Per ADR-141 the projector accepts deprecated v1 dimension labels (risk_levels
// → accountability, etc.) on input by canonicalising via the same
// envelope.CanonicaliseImdaDimension rule.
//
// Idempotency: each evidence aggregate Append is keyed on the IncomingEvent.EventID
// (the envelope event_id) — re-delivery from at-least-once event bus is a no-op
// at the repo layer.
package projector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

// IncomingEvent is the projector's input contract. It mirrors the union of
// payload fields the various S2-S6 services may publish for IMDA evidence.
//
// Only the dimension-relevant subset is required per call; the projector
// validates downstream by routing to the appropriate aggregate constructor.
//
// JSON tags use snake_case to mirror envelope.proto + event bus event payload
// conventions; the synchronous HTTP entry at /v1/governance/evidence/project
// shares this shape with the event bus subscriber wiring.
type IncomingEvent struct {
	// Envelope-derived fields
	EventID        string `json:"event_id"`
	TenantID       string `json:"tenant_id"`
	ImdaDimension  string `json:"imda_dimension"`
	LifecycleStage string `json:"lifecycle_stage,omitempty"`
	EventType      string `json:"event_type"`
	Traceparent    string `json:"traceparent,omitempty"`

	// OccurredAt is when the underlying EVENT happened, taken from the
	// producer's envelope. Every evidence aggregate records THIS rather than
	// the moment the projector ran: a drained backlog would otherwise stamp a
	// whole span of evidence with one ingest instant (the G2 acceptance
	// projected 54 Armor refusals spanning five days onto a single second).
	// Zero falls back to now in the evidence constructors, so a producer that
	// does not state a time still yields a usable row.
	OccurredAt time.Time `json:"occurred_at,omitempty"`

	// D1 accountability_evidence
	AgentID      string         `json:"agent_id,omitempty"`
	OwnerGcid    string         `json:"owner_gcid,omitempty"`
	DecisionID   string         `json:"decision_id,omitempty"`
	DecisionType string         `json:"decision_type,omitempty"`
	Provenance   map[string]any `json:"provenance,omitempty"`

	// D1 accountability_evidence — crew + cost extension fields per
	// chora-contracts/proto/events/observability/agent_decision.proto
	// fields 12-20 (additive within v1). Forwarded from the
	// AgentDecisionLog consumer + projected into the evidence row's
	// Provenance so the O+ Crews+Agents hierarchy (/o/agents) can
	// group decisions by crew_name + the D3 cost monitoring view can
	// aggregate gen_ai.usage.* tokens across runs.
	CrewName         string `json:"crew_name,omitempty"`
	CrewID           string `json:"crew_id,omitempty"`
	IsResume         bool   `json:"is_resume,omitempty"`
	IsEvalRun        bool   `json:"is_eval_run,omitempty"`
	AdapterVersion   string `json:"adapter_version,omitempty"`
	GuardrailOutcome string `json:"guardrail_outcome,omitempty"`
	PromptTokens     int64  `json:"prompt_tokens,omitempty"`
	CompletionTokens int64  `json:"completion_tokens,omitempty"`
	CachedTokens     int64  `json:"cached_tokens,omitempty"`

	// D2 model_card_registry
	ModelID              string         `json:"model_id,omitempty"`
	ModelVersion         string         `json:"model_version,omitempty"`
	CardMD               string         `json:"card_md,omitempty"`
	TrainingDataSummary  string         `json:"training_data_summary,omitempty"`
	IntendedUses         string         `json:"intended_uses,omitempty"`
	Limitations          string         `json:"limitations,omitempty"`
	FairnessAttestations map[string]any `json:"fairness_attestations,omitempty"`

	// D2 data_card_registry
	DatasetID      string         `json:"dataset_id,omitempty"`
	DatasetVersion string         `json:"dataset_version,omitempty"`
	Schema         map[string]any `json:"schema,omitempty"`
	DataProvenance string         `json:"data_provenance,omitempty"`

	// D2 decision_explanation (Three-Audience)
	Audience        string  `json:"audience,omitempty"`
	ExplanationMD   string  `json:"explanation_md,omitempty"`
	ConfidenceScore float64 `json:"confidence_score,omitempty"`

	// D3 red_team_runs / eval_runs / cost_anomalies
	RunID          string         `json:"run_id,omitempty"`
	Scenario       map[string]any `json:"scenario,omitempty"`
	Verdict        string         `json:"verdict,omitempty"`
	Findings       map[string]any `json:"findings,omitempty"`
	EvalSuite      string         `json:"eval_suite,omitempty"`
	Score          float64        `json:"score,omitempty"`
	BaselineScore  float64        `json:"baseline_score,omitempty"`
	AnomalyID      string         `json:"anomaly_id,omitempty"`
	BaselineMicros int64          `json:"baseline_micros,omitempty"`
	ObservedMicros int64          `json:"observed_micros,omitempty"`
	SigmaFactor    float64        `json:"sigma_factor,omitempty"`

	// D4 bias_test_runs / hitl_decision_log
	ProtectedAttribute string         `json:"protected_attribute,omitempty"`
	TestType           string         `json:"test_type,omitempty"`
	Threshold          float64        `json:"threshold,omitempty"`
	OperatorGcid       string         `json:"operator_gcid,omitempty"`
	HitlVerdict        string         `json:"hitl_verdict,omitempty"`
	AutonomyLevel      string         `json:"autonomy_level,omitempty"`
	EditPayload        map[string]any `json:"edit_payload,omitempty"`
	// Summary / Reason carry the human-readable WHY of a HITL escalation
	// (chora.governance.hitl.requested.v1 emits both — `summary` is the
	// primary, `reason` a mirror). They are preserved on the pending
	// hitl_decision_log row (via the reserved note edit_payload key) so the
	// O+ Human-Oversight queue can render WHY the gate was raised.
	Summary string `json:"summary,omitempty"`
	Reason  string `json:"reason,omitempty"`

	// PolicyViolation
	PolicyName string         `json:"policy_name,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	Detector   string         `json:"detector,omitempty"`
	Payload    map[string]any `json:"payload,omitempty"`
}

// Projector routes incoming events into the right evidence aggregate.
type Projector struct {
	repo evidence.Repository
}

// New constructs a projector over the supplied repo.
func New(repo evidence.Repository) *Projector {
	return &Projector{repo: repo}
}

// Project routes ev to the appropriate D1-D4 aggregate. Returns nil on
// successful idempotent application; an error on validation or a routing
// miss for the supplied dimension.
func (p *Projector) Project(ctx context.Context, ev IncomingEvent) error {
	if p == nil || p.repo == nil {
		return errors.New("projector: not initialised")
	}

	dim := canonicaliseDimension(ev.ImdaDimension)
	if dim == "" {
		return fmt.Errorf("projector: imda_dimension is required")
	}

	stage := evidence.LifecycleStage(strings.ToLower(strings.TrimSpace(ev.LifecycleStage)))

	switch dim {
	case "accountability":
		return p.routeD1(ctx, ev, stage)
	case "transparency":
		return p.routeD2(ctx, ev, stage)
	case "safety_and_robustness":
		return p.routeD3(ctx, ev, stage)
	case "fairness_and_human_oversight":
		return p.routeD4(ctx, ev, stage)
	default:
		return fmt.Errorf("projector: unknown imda_dimension %q", ev.ImdaDimension)
	}
}

// -----------------------------------------------------------------------------
// D1 accountability_evidence
// -----------------------------------------------------------------------------

func (p *Projector) routeD1(ctx context.Context, ev IncomingEvent, stage evidence.LifecycleStage) error {
	// Merge the crew + cost extension fields into the Provenance map so
	// the evidence row carries them queryable by /o/agents (crew_name
	// drives the Crews+Agents hierarchy) + /o/governance (Decision
	// Traces drilldown) + D3 cost monitoring. Keep the original
	// Provenance entries — they cover assist-specific context (decision,
	// attempt_count, etc.) that the AgentDecisionLog consumer stamps.
	prov := mergeAccountabilityProvenance(ev)
	a, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID:        ev.EventID,
		TenantID:       ev.TenantID,
		AgentID:        ev.AgentID,
		OwnerGcid:      ev.OwnerGcid,
		DecisionID:     ev.DecisionID,
		DecisionType:   ev.DecisionType,
		Provenance:     prov,
		LifecycleStage: stage,
		Traceparent:    ev.Traceparent,
		OccurredAt:     ev.OccurredAt,
	})
	if err != nil {
		return fmt.Errorf("projector D1: %w", err)
	}
	return p.repo.AppendAccountability(ctx, a)
}

// mergeAccountabilityProvenance stamps the IncomingEvent's extension
// fields onto the Provenance map so the evidence row carries them. When
// the caller supplied a Provenance map AND set the extension fields
// directly (the AgentDecisionLog consumer path does both for forward
// compat), the extension-field values win — they are the canonical
// source.
//
// Returns a new map; never mutates ev.Provenance.
func mergeAccountabilityProvenance(ev IncomingEvent) map[string]any {
	out := make(map[string]any, len(ev.Provenance)+9)
	for k, v := range ev.Provenance {
		out[k] = v
	}
	if ev.CrewName != "" {
		out["crew_name"] = ev.CrewName
	}
	if ev.CrewID != "" {
		out["crew_id"] = ev.CrewID
	}
	if ev.IsResume {
		out["is_resume"] = ev.IsResume
	}
	if ev.IsEvalRun {
		out["is_eval_run"] = ev.IsEvalRun
	}
	if ev.AdapterVersion != "" {
		out["adapter_version"] = ev.AdapterVersion
	}
	if ev.GuardrailOutcome != "" {
		out["guardrail_outcome"] = ev.GuardrailOutcome
	}
	if ev.PromptTokens != 0 {
		out["prompt_tokens"] = ev.PromptTokens
	}
	if ev.CompletionTokens != 0 {
		out["completion_tokens"] = ev.CompletionTokens
	}
	if ev.CachedTokens != 0 {
		out["cached_tokens"] = ev.CachedTokens
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// -----------------------------------------------------------------------------
// D2 transparency
// -----------------------------------------------------------------------------

func (p *Projector) routeD2(ctx context.Context, ev IncomingEvent, stage evidence.LifecycleStage) error {
	et := strings.ToLower(ev.EventType)
	switch {
	case strings.Contains(et, "model_card"):
		c, err := evidence.NewModelCard(evidence.ModelCardParams{
			EventID:              ev.EventID,
			TenantID:             ev.TenantID,
			ModelID:              ev.ModelID,
			ModelVersion:         ev.ModelVersion,
			CardMD:               ev.CardMD,
			TrainingDataSummary:  ev.TrainingDataSummary,
			IntendedUses:         ev.IntendedUses,
			Limitations:          ev.Limitations,
			FairnessAttestations: ev.FairnessAttestations,
			LifecycleStage:       stage,
			OccurredAt:           ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D2 model_card: %w", err)
		}
		return p.repo.AppendModelCard(ctx, c)
	case strings.Contains(et, "data_card"):
		d, err := evidence.NewDataCard(evidence.DataCardParams{
			EventID:        ev.EventID,
			TenantID:       ev.TenantID,
			DatasetID:      ev.DatasetID,
			DatasetVersion: ev.DatasetVersion,
			CardMD:         ev.CardMD,
			Schema:         ev.Schema,
			Provenance:     ev.DataProvenance,
			LifecycleStage: stage,
			OccurredAt:     ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D2 data_card: %w", err)
		}
		return p.repo.AppendDataCard(ctx, d)
	default:
		// Decision-explanation default — Three-Audience
		audience := evidence.Audience(strings.ToLower(strings.TrimSpace(ev.Audience)))
		if audience == "" {
			audience = evidence.AudienceAuditor // most permissive default
		}
		e, err := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
			EventID:         ev.EventID,
			TenantID:        ev.TenantID,
			DecisionID:      ev.DecisionID,
			Audience:        audience,
			ExplanationMD:   ev.ExplanationMD,
			ConfidenceScore: ev.ConfidenceScore,
			LifecycleStage:  stage,
			OccurredAt:      ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D2 decision_explanation: %w", err)
		}
		return p.repo.AppendDecisionExplanation(ctx, e)
	}
}

// -----------------------------------------------------------------------------
// D3 safety_and_robustness
// -----------------------------------------------------------------------------

func (p *Projector) routeD3(ctx context.Context, ev IncomingEvent, stage evidence.LifecycleStage) error {
	et := strings.ToLower(ev.EventType)
	switch {
	case strings.Contains(et, "red_team") || strings.Contains(et, "security_scan"):
		r, err := evidence.NewRedTeamRun(evidence.RedTeamRunParams{
			EventID:        ev.EventID,
			TenantID:       ev.TenantID,
			RunID:          ev.RunID,
			AgentID:        ev.AgentID,
			Scenario:       ev.Scenario,
			Verdict:        ev.Verdict,
			Findings:       ev.Findings,
			LifecycleStage: stage,
			OccurredAt:     ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D3 red_team: %w", err)
		}
		return p.repo.AppendRedTeamRun(ctx, r)
	case strings.Contains(et, "eval"):
		r, err := evidence.NewEvalRun(evidence.EvalRunParams{
			EventID:        ev.EventID,
			TenantID:       ev.TenantID,
			RunID:          ev.RunID,
			AgentID:        ev.AgentID,
			EvalSuite:      ev.EvalSuite,
			Score:          ev.Score,
			BaselineScore:  ev.BaselineScore,
			LifecycleStage: stage,
			OccurredAt:     ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D3 eval: %w", err)
		}
		return p.repo.AppendEvalRun(ctx, r)
	case strings.Contains(et, "cost_anomaly"):
		a, err := evidence.NewCostAnomaly(evidence.CostAnomalyParams{
			EventID:        ev.EventID,
			TenantID:       ev.TenantID,
			AnomalyID:      ev.AnomalyID,
			AgentID:        ev.AgentID,
			BaselineMicros: ev.BaselineMicros,
			ObservedMicros: ev.ObservedMicros,
			SigmaFactor:    ev.SigmaFactor,
			LifecycleStage: stage,
			OccurredAt:     ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D3 cost_anomaly: %w", err)
		}
		return p.repo.AppendCostAnomaly(ctx, a)
	case strings.Contains(et, "content_policy_violation") || strings.Contains(et, "policy_violation"):
		v, err := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
			EventID:        ev.EventID,
			TenantID:       ev.TenantID,
			AgentID:        ev.AgentID,
			PolicyName:     ev.PolicyName,
			Severity:       ev.Severity,
			Detector:       ev.Detector,
			Payload:        ev.Payload,
			LifecycleStage: stage,
			OccurredAt:     ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D3 policy_violation: %w", err)
		}
		return p.repo.AppendPolicyViolation(ctx, v)
	default:
		return fmt.Errorf("projector D3: no route for event_type %q", ev.EventType)
	}
}

// -----------------------------------------------------------------------------
// D4 fairness_and_human_oversight
// -----------------------------------------------------------------------------

func (p *Projector) routeD4(ctx context.Context, ev IncomingEvent, stage evidence.LifecycleStage) error {
	et := strings.ToLower(ev.EventType)
	switch {
	case strings.Contains(et, "bias"):
		r, err := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
			EventID:            ev.EventID,
			TenantID:           ev.TenantID,
			RunID:              ev.RunID,
			AgentID:            ev.AgentID,
			ProtectedAttribute: ev.ProtectedAttribute,
			TestType:           ev.TestType,
			Score:              ev.Score,
			Threshold:          ev.Threshold,
			LifecycleStage:     stage,
			OccurredAt:         ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D4 bias: %w", err)
		}
		return p.repo.AppendBiasTestRun(ctx, r)
	case strings.Contains(et, "hitl"):
		verdict := evidence.HitlVerdict(strings.ToLower(strings.TrimSpace(ev.HitlVerdict)))
		autonomy := evidence.AutonomyLevel(strings.ToLower(strings.TrimSpace(ev.AutonomyLevel)))
		// Pending-gate path: a HITL gate REQUESTED by an automated escalation
		// (e.g. qgen exhausting retries — chora.governance.hitl.requested.v1)
		// carries no operator + a "pending"/blank verdict. It enqueues a
		// PENDING hitl_decision_log row that the O+ Human-Oversight queue
		// surfaces (the existing Claim/Approve/Reject lifecycle resolves it
		// later by APPENDING a verdict row). Distinct from the RESOLVED path
		// below which records a terminal approve|reject|edit + operator.
		if verdict.IsPending() {
			d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
				EventID:        ev.EventID,
				TenantID:       ev.TenantID,
				DecisionID:     ev.DecisionID,
				RunID:          ev.RunID,
				AutonomyLevel:  autonomy,
				Summary:        hitlSummary(ev),
				EditPayload:    ev.EditPayload,
				LifecycleStage: stage,
				AgentID:        ev.AgentID,
				OccurredAt:     ev.OccurredAt,
			})
			if err != nil {
				return fmt.Errorf("projector D4 hitl pending: %w", err)
			}
			return p.repo.AppendHITLDecision(ctx, d)
		}
		d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
			EventID:        ev.EventID,
			TenantID:       ev.TenantID,
			DecisionID:     ev.DecisionID,
			RunID:          ev.RunID,
			OperatorGcid:   ev.OperatorGcid,
			Decision:       verdict,
			AutonomyLevel:  autonomy,
			EditPayload:    ev.EditPayload,
			LifecycleStage: stage,
			OccurredAt:     ev.OccurredAt,
		})
		if err != nil {
			return fmt.Errorf("projector D4 hitl: %w", err)
		}
		return p.repo.AppendHITLDecision(ctx, d)
	default:
		return fmt.Errorf("projector D4: no route for event_type %q", ev.EventType)
	}
}

// hitlSummary returns the human-readable WHY of a HITL escalation: prefer the
// `summary` field, fall back to `reason`. Empty when neither is set (the
// pending row then carries no note).
func hitlSummary(ev IncomingEvent) string {
	if s := strings.TrimSpace(ev.Summary); s != "" {
		return s
	}
	return strings.TrimSpace(ev.Reason)
}

// -----------------------------------------------------------------------------
// canonicaliseDimension mirrors envelope.CanonicaliseImdaDimension. We
// duplicate it here so the governance service does not pull the chora-common
// envelope package transitively.
// -----------------------------------------------------------------------------

var v1ToCanonical = map[string]string{
	"risk_levels":             "accountability",
	"stakeholder_interaction": "transparency",
	"internal_governance":     "safety_and_robustness",
	"operations_management":   "fairness_and_human_oversight",
}

func canonicaliseDimension(in string) string {
	v := strings.ToLower(strings.TrimSpace(in))
	if v == "" {
		return ""
	}
	if mapped, ok := v1ToCanonical[v]; ok {
		return mapped
	}
	return v
}
