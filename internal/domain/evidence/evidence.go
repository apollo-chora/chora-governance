// Package evidence is the IMDA D1-D4 evidence aggregate of the Governance domain.
//
// Per CLAUDE.md §1 (IMDA Model AI Governance Framework as NorthStar) +
// ADR-141 (canonical labels accountability/transparency/safety_and_robustness/
// fairness_and_human_oversight) + audit-platform-fillgaps.md §3.3 + §5
// (all 11 D1-D4 evidence tables missing), this package implements the 11
// production evidence aggregates that feed the O+ governance dashboard and
// the IMDA evidence-pack export.
//
// Aggregates:
//
//	D1 accountability_evidence — AccountabilityEvidence
//	D2 model_card_registry     — ModelCard
//	D2 data_card_registry      — DataCard
//	D2 decision_explanation    — DecisionExplanation (Three-Audience)
//	D3 red_team_runs           — RedTeamRun
//	D3 eval_runs               — EvalRun
//	D3 cost_anomalies          — CostAnomaly
//	D3 circuit_breaker_state   — CircuitBreaker (state machine)
//	D3 quarantine_state        — Quarantine    (state machine)
//	D4 bias_test_runs          — BiasTestRun
//	D4 hitl_decision_log       — HITLDecision
//	+  policy_violation_log    — PolicyViolation (Tier 3 D9 ContentPolicyViolationLog)
//
// All append-only aggregates carry an immutable EventID + LifecycleStage tag
// so re-delivery from at-least-once event bus is idempotent at the repo layer.
//
// LifecycleStage tagging mirrors envelope.proto field 15 + the canonical set
// in chora-common/envelope/envelope.go.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// LifecycleStage — closed enum per envelope.proto field 15
// =============================================================================

// LifecycleStage is the 4-stage IMDA pipeline classifier per the
// imda-governance-4-dimensions skill.
type LifecycleStage string

const (
	// LifecycleCIPreMerge — CI/pre-merge linting + static analysis evidence.
	LifecycleCIPreMerge LifecycleStage = "ci_pre_merge"
	// LifecyclePreDeploy — red-team + eval runs in CI before deploy gates.
	LifecyclePreDeploy LifecycleStage = "pre_deploy"
	// LifecycleRuntime — default for runtime-emitted evidence.
	LifecycleRuntime LifecycleStage = "runtime"
	// LifecyclePostDeploy — incident reports, drift detection, post-mortem.
	LifecyclePostDeploy LifecycleStage = "post_deploy"
)

// Valid reports whether s is one of the 4 canonical lifecycle stages.
func (s LifecycleStage) Valid() bool {
	switch s {
	case LifecycleCIPreMerge, LifecyclePreDeploy, LifecycleRuntime, LifecyclePostDeploy:
		return true
	}
	return false
}

// =============================================================================
// Audience — Three-Audience explainability per Tier 4 D16
// =============================================================================

// Audience is one of the three explainability audiences per Tier 4 D16.
// Role-driven feature visibility (NOT toggle).
type Audience string

const (
	// AudienceLearner is the learner-facing explanation in A+.
	AudienceLearner Audience = "learner"
	// AudienceInstructorAdmin is the operator-grade explanation in R+/H+.
	AudienceInstructorAdmin Audience = "instructor_admin"
	// AudienceAuditor is the full provenance + technical explanation in O+.
	AudienceAuditor Audience = "auditor"
)

// Valid reports whether a is one of the three canonical audiences.
func (a Audience) Valid() bool {
	switch a {
	case AudienceLearner, AudienceInstructorAdmin, AudienceAuditor:
		return true
	}
	return false
}

// =============================================================================
// AutonomyLevel — Level 0-2 only; Level 3 PROHIBITED per ADR-141
// =============================================================================

// AutonomyLevel maps Chora Level 0-2 = NVIDIA Level 0-2 = HOOTL/HOTL/HITL.
// Per imda-governance-4-dimensions skill + ADR-141 §3, Level 3 (out-of-band
// autonomous) is PROHIBITED — Valid() rejects it.
type AutonomyLevel string

const (
	// AutonomyHootl — Level 0: human-out-of-the-loop (low-stakes).
	AutonomyHootl AutonomyLevel = "hootl"
	// AutonomyHotl — Level 1: human-on-the-loop (autonomous + monitoring).
	AutonomyHotl AutonomyLevel = "hotl"
	// AutonomyHitlL0 — Level 2: human-in-the-loop, sampling review.
	AutonomyHitlL0 AutonomyLevel = "hitl_l0"
	// AutonomyHitlL1 — Level 2: human-in-the-loop, mandatory per Nth output.
	AutonomyHitlL1 AutonomyLevel = "hitl_l1"
	// AutonomyHitlL2 — Level 2: human-in-the-loop, mandatory every output.
	AutonomyHitlL2 AutonomyLevel = "hitl_l2"
)

// Valid reports whether l is one of the canonical Level 0-2 values.
// Level 3 (hitl_l3 / level_3) is rejected.
func (l AutonomyLevel) Valid() bool {
	switch l {
	case AutonomyHootl, AutonomyHotl, AutonomyHitlL0, AutonomyHitlL1, AutonomyHitlL2:
		return true
	}
	return false
}

// =============================================================================
// HitlVerdict + CircuitBreakerState
// =============================================================================

// HitlVerdict is the operator's HITL decision verdict.
type HitlVerdict string

const (
	HitlApprove HitlVerdict = "approve"
	HitlReject  HitlVerdict = "reject"
	HitlEdit    HitlVerdict = "edit"

	// HitlPending is the PRE-VERDICT sentinel for a HITL gate that has been
	// raised (e.g. by a qgen escalation) but not yet decided by an operator.
	// It is DELIBERATELY excluded from Valid() — terminalVerdict() is defined
	// as Decision.Valid(), so a pending row must report invalid to remain
	// claimable + decidable through the existing Claim/Approve/Reject
	// lifecycle. See NewPendingHITLDecision + ADR-141 HITL lifecycle.
	HitlPending HitlVerdict = "pending"
)

// Valid reports whether v is one of the canonical TERMINAL verdicts.
// HitlPending is intentionally NOT valid (it is the pre-verdict sentinel) —
// see its godoc.
func (v HitlVerdict) Valid() bool {
	switch v {
	case HitlApprove, HitlReject, HitlEdit:
		return true
	}
	return false
}

// IsPending reports whether v is the pre-verdict pending sentinel (the literal
// "pending", or — for forward compat with rows authored before the sentinel
// existed — the empty string).
func (v HitlVerdict) IsPending() bool {
	return v == HitlPending || v == ""
}

// CircuitBreakerState is the tri-state breaker per agent-resilience skill.
type CircuitBreakerState string

const (
	CircuitClosed   CircuitBreakerState = "closed"
	CircuitHalfOpen CircuitBreakerState = "half_open"
	CircuitOpen     CircuitBreakerState = "open"
)

// Valid reports whether s is one of the canonical states.
func (s CircuitBreakerState) Valid() bool {
	switch s {
	case CircuitClosed, CircuitHalfOpen, CircuitOpen:
		return true
	}
	return false
}

// =============================================================================
// D1 accountability_evidence
// =============================================================================

// AccountabilityEvidence is per-agent decision provenance + owner GCID.
// Append-only; identified by EventID for idempotent re-delivery.
type AccountabilityEvidence struct {
	EventID        string         `json:"event_id"`
	TenantID       string         `json:"tenant_id"`
	AgentID        string         `json:"agent_id"`
	OwnerGcid      string         `json:"owner_gcid"`
	DecisionID     string         `json:"decision_id"`
	DecisionType   string         `json:"decision_type"`
	Provenance     map[string]any `json:"provenance"`
	EvidenceHash   string         `json:"evidence_hash"`
	LifecycleStage LifecycleStage `json:"lifecycle_stage"`
	Traceparent    string         `json:"traceparent,omitempty"`
	RecordedAt     time.Time      `json:"recorded_at"`
}

// AccountabilityParams is the constructor input.
// eventTime resolves the timestamp an evidence row records.
//
// An evidence row must carry WHEN THE EVENT HAPPENED, not when the projector
// wrote it. Before 2026-08-14 every params-based constructor stamped
// time.Now(), so a backlog drained in one second produced a whole span of
// evidence sharing one timestamp: the G2 acceptance projected 54 Model Armor
// refusals spanning five days and every row read the same instant, which tells
// an auditor of the exported D3 pack something untrue.
//
// Zero means the caller did not state an event time, so it falls back to now.
// That keeps the change additive: an un-migrated call site still produces a
// sane row rather than a zero-value timestamp, which would be worse than the
// defect being fixed. Non-zero values are normalised to UTC so two rows from
// the same instant compare equal whatever zone the producer used.
//
// NOT used by the CircuitBreaker and Quarantine state machines: those record
// transitions this service performs itself, so their instant genuinely is now.
func eventTime(occurredAt time.Time) time.Time {
	if occurredAt.IsZero() {
		return time.Now().UTC()
	}
	return occurredAt.UTC()
}

type AccountabilityParams struct {
	EventID        string
	TenantID       string
	AgentID        string
	OwnerGcid      string
	DecisionID     string
	DecisionType   string
	Provenance     map[string]any
	LifecycleStage LifecycleStage
	Traceparent    string

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewAccountabilityEvidence constructs a D1 evidence row.
func NewAccountabilityEvidence(p AccountabilityParams) (*AccountabilityEvidence, error) {
	if err := requireNonBlank("event_id", p.EventID); err != nil {
		return nil, err
	}
	if err := requireNonBlank("tenant_id", p.TenantID); err != nil {
		return nil, err
	}
	if err := requireNonBlank("agent_id", p.AgentID); err != nil {
		return nil, err
	}
	if err := requireNonBlank("owner_gcid", p.OwnerGcid); err != nil {
		return nil, err
	}
	if err := requireNonBlank("decision_id", p.DecisionID); err != nil {
		return nil, err
	}
	if err := requireNonBlank("decision_type", p.DecisionType); err != nil {
		return nil, err
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecycleRuntime)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}

	hash := computeEvidenceHash(p)

	return &AccountabilityEvidence{
		EventID:        p.EventID,
		TenantID:       p.TenantID,
		AgentID:        p.AgentID,
		OwnerGcid:      p.OwnerGcid,
		DecisionID:     p.DecisionID,
		DecisionType:   p.DecisionType,
		Provenance:     copyMap(p.Provenance),
		EvidenceHash:   hash,
		LifecycleStage: stage,
		Traceparent:    strings.TrimSpace(p.Traceparent),
		RecordedAt:     eventTime(p.OccurredAt),
	}, nil
}

func computeEvidenceHash(p AccountabilityParams) string {
	provBytes, _ := json.Marshal(canonicaliseMap(p.Provenance))
	var b strings.Builder
	b.WriteString(p.EventID)
	b.WriteByte('|')
	b.WriteString(p.TenantID)
	b.WriteByte('|')
	b.WriteString(p.AgentID)
	b.WriteByte('|')
	b.WriteString(p.OwnerGcid)
	b.WriteByte('|')
	b.WriteString(p.DecisionID)
	b.WriteByte('|')
	b.WriteString(p.DecisionType)
	b.WriteByte('|')
	b.Write(provBytes)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// canonicaliseMap returns a stable representation by sorting keys recursively.
func canonicaliseMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]any, len(m))
	for _, k := range keys {
		v := m[k]
		switch vv := v.(type) {
		case map[string]any:
			out[k] = canonicaliseMap(vv)
		default:
			out[k] = vv
		}
	}
	return out
}

// =============================================================================
// D2 model_card_registry
// =============================================================================

// ModelCard is a registered model card.
type ModelCard struct {
	EventID              string         `json:"event_id"`
	TenantID             string         `json:"tenant_id"`
	ModelID              string         `json:"model_id"`
	ModelVersion         string         `json:"model_version"`
	CardMD               string         `json:"card_md"`
	TrainingDataSummary  string         `json:"training_data_summary"`
	IntendedUses         string         `json:"intended_uses"`
	Limitations          string         `json:"limitations"`
	FairnessAttestations map[string]any `json:"fairness_attestations"`
	LifecycleStage       LifecycleStage `json:"lifecycle_stage"`
	RegisteredAt         time.Time      `json:"registered_at"`
}

// ModelCardParams is the constructor input.
type ModelCardParams struct {
	EventID              string
	TenantID             string
	ModelID              string
	ModelVersion         string
	CardMD               string
	TrainingDataSummary  string
	IntendedUses         string
	Limitations          string
	FairnessAttestations map[string]any
	LifecycleStage       LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewModelCard constructs a D2 ModelCard.
func NewModelCard(p ModelCardParams) (*ModelCard, error) {
	for k, v := range map[string]string{
		"event_id":      p.EventID,
		"tenant_id":     p.TenantID,
		"model_id":      p.ModelID,
		"model_version": p.ModelVersion,
		"card_md":       p.CardMD,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecycleRuntime)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	return &ModelCard{
		EventID:              p.EventID,
		TenantID:             p.TenantID,
		ModelID:              p.ModelID,
		ModelVersion:         p.ModelVersion,
		CardMD:               p.CardMD,
		TrainingDataSummary:  p.TrainingDataSummary,
		IntendedUses:         p.IntendedUses,
		Limitations:          p.Limitations,
		FairnessAttestations: copyMap(p.FairnessAttestations),
		LifecycleStage:       stage,
		RegisteredAt:         eventTime(p.OccurredAt),
	}, nil
}

// =============================================================================
// D2 data_card_registry
// =============================================================================

// DataCard is a registered data card.
type DataCard struct {
	EventID        string         `json:"event_id"`
	TenantID       string         `json:"tenant_id"`
	DatasetID      string         `json:"dataset_id"`
	DatasetVersion string         `json:"dataset_version"`
	CardMD         string         `json:"card_md"`
	Schema         map[string]any `json:"schema"`
	Provenance     string         `json:"provenance"`
	LifecycleStage LifecycleStage `json:"lifecycle_stage"`
	RegisteredAt   time.Time      `json:"registered_at"`
}

// DataCardParams is the constructor input.
type DataCardParams struct {
	EventID        string
	TenantID       string
	DatasetID      string
	DatasetVersion string
	CardMD         string
	Schema         map[string]any
	Provenance     string
	LifecycleStage LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewDataCard constructs a D2 DataCard.
func NewDataCard(p DataCardParams) (*DataCard, error) {
	for k, v := range map[string]string{
		"event_id":        p.EventID,
		"tenant_id":       p.TenantID,
		"dataset_id":      p.DatasetID,
		"dataset_version": p.DatasetVersion,
		"card_md":         p.CardMD,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecycleRuntime)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	return &DataCard{
		EventID:        p.EventID,
		TenantID:       p.TenantID,
		DatasetID:      p.DatasetID,
		DatasetVersion: p.DatasetVersion,
		CardMD:         p.CardMD,
		Schema:         copyMap(p.Schema),
		Provenance:     p.Provenance,
		LifecycleStage: stage,
		RegisteredAt:   eventTime(p.OccurredAt),
	}, nil
}

// =============================================================================
// D2 decision_explanation (Three-Audience)
// =============================================================================

// DecisionExplanation is one explanation row for a decision, scoped by Audience.
type DecisionExplanation struct {
	EventID         string         `json:"event_id"`
	TenantID        string         `json:"tenant_id"`
	DecisionID      string         `json:"decision_id"`
	Audience        Audience       `json:"audience"`
	ExplanationMD   string         `json:"explanation_md"`
	ConfidenceScore float64        `json:"confidence_score"`
	LifecycleStage  LifecycleStage `json:"lifecycle_stage"`
	GeneratedAt     time.Time      `json:"generated_at"`
}

// DecisionExplanationParams is the constructor input.
type DecisionExplanationParams struct {
	EventID         string
	TenantID        string
	DecisionID      string
	Audience        Audience
	ExplanationMD   string
	ConfidenceScore float64
	LifecycleStage  LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewDecisionExplanation constructs a D2 explanation row.
func NewDecisionExplanation(p DecisionExplanationParams) (*DecisionExplanation, error) {
	for k, v := range map[string]string{
		"event_id":       p.EventID,
		"tenant_id":      p.TenantID,
		"decision_id":    p.DecisionID,
		"explanation_md": p.ExplanationMD,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	if !p.Audience.Valid() {
		return nil, fmt.Errorf("invalid audience: %q (must be learner|instructor_admin|auditor)", p.Audience)
	}
	if p.ConfidenceScore < 0 || p.ConfidenceScore > 1 {
		return nil, fmt.Errorf("confidence_score out of range: %v (must be 0..1)", p.ConfidenceScore)
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecycleRuntime)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	return &DecisionExplanation{
		EventID:         p.EventID,
		TenantID:        p.TenantID,
		DecisionID:      p.DecisionID,
		Audience:        p.Audience,
		ExplanationMD:   p.ExplanationMD,
		ConfidenceScore: p.ConfidenceScore,
		LifecycleStage:  stage,
		GeneratedAt:     eventTime(p.OccurredAt),
	}, nil
}

// =============================================================================
// D3 red_team_runs
// =============================================================================

// RedTeamRun is a single deepteam adversarial run result.
type RedTeamRun struct {
	EventID        string         `json:"event_id"`
	TenantID       string         `json:"tenant_id"`
	RunID          string         `json:"run_id"`
	AgentID        string         `json:"agent_id"`
	Scenario       map[string]any `json:"scenario"`
	Verdict        string         `json:"verdict"`
	Findings       map[string]any `json:"findings"`
	LifecycleStage LifecycleStage `json:"lifecycle_stage"`
	RunAt          time.Time      `json:"run_at"`
}

// RedTeamRunParams is the constructor input.
type RedTeamRunParams struct {
	EventID        string
	TenantID       string
	RunID          string
	AgentID        string
	Scenario       map[string]any
	Verdict        string
	Findings       map[string]any
	LifecycleStage LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewRedTeamRun constructs a D3 red-team run row.
func NewRedTeamRun(p RedTeamRunParams) (*RedTeamRun, error) {
	for k, v := range map[string]string{
		"event_id":  p.EventID,
		"tenant_id": p.TenantID,
		"run_id":    p.RunID,
		"agent_id":  p.AgentID,
		"verdict":   p.Verdict,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecyclePreDeploy)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	return &RedTeamRun{
		EventID:        p.EventID,
		TenantID:       p.TenantID,
		RunID:          p.RunID,
		AgentID:        p.AgentID,
		Scenario:       copyMap(p.Scenario),
		Verdict:        p.Verdict,
		Findings:       copyMap(p.Findings),
		LifecycleStage: stage,
		RunAt:          eventTime(p.OccurredAt),
	}, nil
}

// =============================================================================
// D3 eval_runs
// =============================================================================

// EvalRun is a single eval-suite run (deepeval / promptfoo).
type EvalRun struct {
	EventID        string         `json:"event_id"`
	TenantID       string         `json:"tenant_id"`
	RunID          string         `json:"run_id"`
	AgentID        string         `json:"agent_id"`
	EvalSuite      string         `json:"eval_suite"`
	Score          float64        `json:"score"`
	BaselineScore  float64        `json:"baseline_score"`
	Regressed      bool           `json:"regressed"`
	LifecycleStage LifecycleStage `json:"lifecycle_stage"`
	RunAt          time.Time      `json:"run_at"`
}

// EvalRunParams is the constructor input.
type EvalRunParams struct {
	EventID        string
	TenantID       string
	RunID          string
	AgentID        string
	EvalSuite      string
	Score          float64
	BaselineScore  float64
	LifecycleStage LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewEvalRun constructs a D3 eval-run row. Auto-derives Regressed from
// Score < BaselineScore.
func NewEvalRun(p EvalRunParams) (*EvalRun, error) {
	for k, v := range map[string]string{
		"event_id":   p.EventID,
		"tenant_id":  p.TenantID,
		"run_id":     p.RunID,
		"agent_id":   p.AgentID,
		"eval_suite": p.EvalSuite,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecyclePreDeploy)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	return &EvalRun{
		EventID:        p.EventID,
		TenantID:       p.TenantID,
		RunID:          p.RunID,
		AgentID:        p.AgentID,
		EvalSuite:      p.EvalSuite,
		Score:          p.Score,
		BaselineScore:  p.BaselineScore,
		Regressed:      p.Score < p.BaselineScore,
		LifecycleStage: stage,
		RunAt:          eventTime(p.OccurredAt),
	}, nil
}

// =============================================================================
// D3 cost_anomalies
// =============================================================================

// CostAnomaly is a single statistical cost outlier.
type CostAnomaly struct {
	EventID        string         `json:"event_id"`
	TenantID       string         `json:"tenant_id"`
	AnomalyID      string         `json:"anomaly_id"`
	AgentID        string         `json:"agent_id"`
	BaselineMicros int64          `json:"baseline_micros"`
	ObservedMicros int64          `json:"observed_micros"`
	SigmaFactor    float64        `json:"sigma_factor"`
	LifecycleStage LifecycleStage `json:"lifecycle_stage"`
	RecordedAt     time.Time      `json:"recorded_at"`
}

// CostAnomalyParams is the constructor input.
type CostAnomalyParams struct {
	EventID        string
	TenantID       string
	AnomalyID      string
	AgentID        string
	BaselineMicros int64
	ObservedMicros int64
	SigmaFactor    float64
	LifecycleStage LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewCostAnomaly constructs a D3 cost-anomaly row.
func NewCostAnomaly(p CostAnomalyParams) (*CostAnomaly, error) {
	for k, v := range map[string]string{
		"event_id":   p.EventID,
		"tenant_id":  p.TenantID,
		"anomaly_id": p.AnomalyID,
		"agent_id":   p.AgentID,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecycleRuntime)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	return &CostAnomaly{
		EventID:        p.EventID,
		TenantID:       p.TenantID,
		AnomalyID:      p.AnomalyID,
		AgentID:        p.AgentID,
		BaselineMicros: p.BaselineMicros,
		ObservedMicros: p.ObservedMicros,
		SigmaFactor:    p.SigmaFactor,
		LifecycleStage: stage,
		RecordedAt:     eventTime(p.OccurredAt),
	}, nil
}

// =============================================================================
// D3 circuit_breaker_state — state machine
// =============================================================================

// circuitOpenThreshold matches the agent-resilience skill's default.
const circuitOpenThreshold = 5

// CircuitBreaker is a per-agent breaker state machine.
type CircuitBreaker struct {
	mu                 sync.RWMutex
	tenantID           string
	agentID            string
	state              CircuitBreakerState
	failureCount       int
	lifecycleStage     LifecycleStage
	lastTransitionedAt time.Time
}

// NewCircuitBreaker constructs a fresh closed breaker for (tenant, agent).
func NewCircuitBreaker(tenantID, agentID string) *CircuitBreaker {
	return &CircuitBreaker{
		tenantID:           tenantID,
		agentID:            agentID,
		state:              CircuitClosed,
		lifecycleStage:     LifecycleRuntime,
		lastTransitionedAt: time.Now().UTC(),
	}
}

// State returns the breaker's current state.
func (c *CircuitBreaker) State() CircuitBreakerState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// FailureCount returns the breaker's consecutive failure tally.
func (c *CircuitBreaker) FailureCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.failureCount
}

// TenantID returns the breaker's tenant.
func (c *CircuitBreaker) TenantID() string { return c.tenantID }

// AgentID returns the breaker's agent.
func (c *CircuitBreaker) AgentID() string { return c.agentID }

// LastTransitionedAt returns the breaker's last transition timestamp.
func (c *CircuitBreaker) LastTransitionedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastTransitionedAt
}

// LifecycleStage returns the breaker's lifecycle stage tag.
func (c *CircuitBreaker) LifecycleStage() LifecycleStage {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lifecycleStage
}

// RecordFailure increments the failure tally; transitions to Open at threshold.
func (c *CircuitBreaker) RecordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failureCount++
	if c.failureCount >= circuitOpenThreshold && c.state != CircuitOpen {
		c.state = CircuitOpen
		c.lastTransitionedAt = time.Now().UTC()
	}
}

// RecordSuccess transitions HalfOpen → Closed (and resets failure tally).
func (c *CircuitBreaker) RecordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failureCount = 0
	if c.state == CircuitHalfOpen {
		c.state = CircuitClosed
		c.lastTransitionedAt = time.Now().UTC()
	}
}

// TransitionTo forces a transition to the supplied state (used by half-open
// trip after Open timeout). No-op when already in target state.
func (c *CircuitBreaker) TransitionTo(s CircuitBreakerState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == s {
		return
	}
	c.state = s
	c.lastTransitionedAt = time.Now().UTC()
}

// =============================================================================
// D3 quarantine_state
// =============================================================================

// Quarantine is a per-agent quarantine state record.
type Quarantine struct {
	TenantID       string
	AgentID        string
	Reason         string
	LifecycleStage LifecycleStage
	QuarantinedAt  time.Time
	ReleasedAt     *time.Time
}

// NewQuarantine constructs a fresh active quarantine.
func NewQuarantine(tenantID, agentID, reason string) *Quarantine {
	return &Quarantine{
		TenantID:       tenantID,
		AgentID:        agentID,
		Reason:         reason,
		LifecycleStage: LifecycleRuntime,
		QuarantinedAt:  time.Now().UTC(),
	}
}

// IsActive reports whether the quarantine is still in effect.
func (q *Quarantine) IsActive() bool {
	return q.ReleasedAt == nil
}

// Release records the quarantine release.
func (q *Quarantine) Release() {
	t := time.Now().UTC()
	q.ReleasedAt = &t
}

// =============================================================================
// D4 bias_test_runs
// =============================================================================

// BiasTestRun is a single bias-test-suite run.
type BiasTestRun struct {
	EventID            string         `json:"event_id"`
	TenantID           string         `json:"tenant_id"`
	RunID              string         `json:"run_id"`
	AgentID            string         `json:"agent_id"`
	ProtectedAttribute string         `json:"protected_attribute"`
	TestType           string         `json:"test_type"`
	Score              float64        `json:"score"`
	Threshold          float64        `json:"threshold"`
	Passed             bool           `json:"passed"`
	LifecycleStage     LifecycleStage `json:"lifecycle_stage"`
	RunAt              time.Time      `json:"run_at"`
}

// BiasTestRunParams is the constructor input.
type BiasTestRunParams struct {
	EventID            string
	TenantID           string
	RunID              string
	AgentID            string
	ProtectedAttribute string
	TestType           string
	Score              float64
	Threshold          float64
	LifecycleStage     LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewBiasTestRun constructs a D4 bias-test row. Passed is auto-derived from
// Score >= Threshold.
func NewBiasTestRun(p BiasTestRunParams) (*BiasTestRun, error) {
	for k, v := range map[string]string{
		"event_id":            p.EventID,
		"tenant_id":           p.TenantID,
		"run_id":              p.RunID,
		"agent_id":            p.AgentID,
		"protected_attribute": p.ProtectedAttribute,
		"test_type":           p.TestType,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecyclePreDeploy)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	return &BiasTestRun{
		EventID:            p.EventID,
		TenantID:           p.TenantID,
		RunID:              p.RunID,
		AgentID:            p.AgentID,
		ProtectedAttribute: p.ProtectedAttribute,
		TestType:           p.TestType,
		Score:              p.Score,
		Threshold:          p.Threshold,
		Passed:             p.Score >= p.Threshold,
		LifecycleStage:     stage,
		RunAt:              eventTime(p.OccurredAt),
	}, nil
}

// =============================================================================
// D4 hitl_decision_log
// =============================================================================

// HITLDecision is a single HITL operator decision row.
//
// OperatorGcid vs AssigneeGcid — these are SEMANTICALLY DISTINCT:
//
//   - OperatorGcid is the auditor who DECIDED the gate (recorded a verdict).
//     Required at verdict-time; immutable on the append-only row.
//   - AssigneeGcid is the auditor currently RESPONSIBLE for a pending gate.
//     NULL = unassigned (default at creation). Set when a reviewer claims
//     the gate via the (deferred to wave N+1) POST /api/hitl/decisions/{id}/claim
//     endpoint. NEVER backfilled with OperatorGcid at verdict time.
//
// Both fields can co-exist on the same row (e.g. Alice claimed → Alice
// decided), but AssigneeGcid may also remain NULL on a row that's already
// decided (e.g. the gate auto-resolved without ever being claimed).
type HITLDecision struct {
	EventID       string         `json:"event_id"`
	TenantID      string         `json:"tenant_id"`
	DecisionID    string         `json:"decision_id"`
	RunID         string         `json:"run_id"`
	OperatorGcid  string         `json:"operator_gcid"`
	AssigneeGcid  *string        `json:"assignee_gcid"`
	Decision      HitlVerdict    `json:"decision"`
	AutonomyLevel AutonomyLevel  `json:"autonomy_level"`
	EditPayload   map[string]any `json:"edit_payload"`
	// Note is the operator's optional free-text rationale recorded alongside
	// an approve/reject verdict. There is NO dedicated `note` column on
	// hitl_decision_log (migration 0003) — the value is persisted into the
	// existing `edit_payload` JSONB under the reserved key NoteEditPayloadKey
	// and surfaced back onto this field on load. See Approve/Reject.
	Note           string         `json:"note,omitempty"`
	LifecycleStage LifecycleStage `json:"lifecycle_stage"`
	DecidedAt      time.Time      `json:"decided_at"`
}

// NoteEditPayloadKey is the reserved edit_payload JSONB key under which the
// operator's verdict note is persisted. Chosen over a new schema column to
// stay least-invasive — adding a column would require a new migration AND an
// amendment to migration 0009's assignee-only-update trigger column list.
const NoteEditPayloadKey = "operator_note"

// AgentIDEditPayloadKey is the reserved edit_payload JSONB key carrying the
// emitting agent of a PENDING gate (CHO-2368 P2). Same least-invasive ride as
// NoteEditPayloadKey — no dedicated column.
const AgentIDEditPayloadKey = "agent_id"

// HITLDecisionParams is the constructor input.
//
// AssigneeGcid is optional (NULL = unassigned). When non-nil, the value is
// trimmed; an empty-after-trim string is rejected (callers must pass nil
// rather than a synthetic blank, per [[feedback-no-stubs-real-wiring]]).
type HITLDecisionParams struct {
	EventID        string
	TenantID       string
	DecisionID     string
	RunID          string
	OperatorGcid   string
	AssigneeGcid   *string
	Decision       HitlVerdict
	AutonomyLevel  AutonomyLevel
	EditPayload    map[string]any
	LifecycleStage LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewHITLDecision constructs a D4 HITL decision row. Rejects Level 3
// autonomy per ADR-141.
func NewHITLDecision(p HITLDecisionParams) (*HITLDecision, error) {
	for k, v := range map[string]string{
		"event_id":      p.EventID,
		"tenant_id":     p.TenantID,
		"decision_id":   p.DecisionID,
		"run_id":        p.RunID,
		"operator_gcid": p.OperatorGcid,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	if !p.Decision.Valid() {
		return nil, fmt.Errorf("invalid decision: %q (must be approve|reject|edit)", p.Decision)
	}
	if !p.AutonomyLevel.Valid() {
		return nil, fmt.Errorf("invalid autonomy_level: %q (Level 3 PROHIBITED per ADR-141)", p.AutonomyLevel)
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecycleRuntime)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	assignee, err := canonicaliseAssigneeGcid(p.AssigneeGcid)
	if err != nil {
		return nil, err
	}
	return &HITLDecision{
		EventID:        p.EventID,
		TenantID:       p.TenantID,
		DecisionID:     p.DecisionID,
		RunID:          p.RunID,
		OperatorGcid:   p.OperatorGcid,
		AssigneeGcid:   assignee,
		Decision:       p.Decision,
		AutonomyLevel:  p.AutonomyLevel,
		EditPayload:    copyMap(p.EditPayload),
		LifecycleStage: stage,
		DecidedAt:      eventTime(p.OccurredAt),
	}, nil
}

// PendingHITLDecisionParams is the constructor input for a PENDING HITL gate.
//
// Unlike HITLDecisionParams it carries NO OperatorGcid (no one has decided)
// and NO Decision (the verdict sentinel is forced to HitlPending). The gate is
// raised by an automated escalation (e.g. qgen exhausting retries with a
// quality warning) and sits in the O+ Human-Oversight queue until a reviewer
// claims + decides it.
//
// Summary is the human-readable WHY of the escalation. It is preserved on the
// row under the reserved NoteEditPayloadKey edit_payload key (and surfaced back
// onto HITLDecision.Note) so the O+ queue can render it without a separate
// column. AutonomyLevel defaults to AutonomyHitlL0 (the canonical escalation
// level) when blank; LifecycleStage defaults to LifecycleRuntime.
type PendingHITLDecisionParams struct {
	EventID        string
	TenantID       string
	DecisionID     string
	RunID          string
	AutonomyLevel  AutonomyLevel
	Summary        string
	EditPayload    map[string]any
	LifecycleStage LifecycleStage
	// AgentID is the emitting agent (e.g. "prompt-registry"). Persisted into
	// edit_payload under AgentIDEditPayloadKey (no dedicated column — same
	// least-invasive pattern as the operator note) so the O+ pending card can
	// show WHICH agent raised the gate (CHO-2368 P2).
	AgentID string

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewPendingHITLDecision constructs a PENDING HITL gate row: Decision is forced
// to HitlPending, OperatorGcid is empty, and AssigneeGcid is nil (unassigned).
// The resulting aggregate is NON-TERMINAL (terminalVerdict()==false), so the
// existing Claim/Approve/Reject lifecycle resolves it later by APPENDING a
// fresh verdict row sharing (tenant_id, decision_id, run_id) — the verdict
// columns are append-only at the DB layer per migration 0009.
//
// Rejects Level 3 autonomy per ADR-141. Requires the four identity fields
// (event_id, tenant_id, decision_id, run_id); deliberately does NOT require
// operator_gcid (a pending gate has no operator).
func NewPendingHITLDecision(p PendingHITLDecisionParams) (*HITLDecision, error) {
	for k, v := range map[string]string{
		"event_id":    p.EventID,
		"tenant_id":   p.TenantID,
		"decision_id": p.DecisionID,
		"run_id":      p.RunID,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	autonomy := p.AutonomyLevel
	if autonomy == "" {
		autonomy = AutonomyHitlL0 // canonical escalation level
	}
	if !autonomy.Valid() {
		return nil, fmt.Errorf("invalid autonomy_level: %q (Level 3 PROHIBITED per ADR-141)", autonomy)
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecycleRuntime)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	// Preserve the escalation summary under the reserved note key so the O+
	// queue surfaces WHY the gate was raised (HITLDecision.Note mirrors it).
	editPayload := copyMap(p.EditPayload)
	note := strings.TrimSpace(p.Summary)
	if note != "" {
		if editPayload == nil {
			editPayload = make(map[string]any, 1)
		}
		editPayload[NoteEditPayloadKey] = note
	}
	// Preserve WHICH agent raised the gate (CHO-2368 P2) — same edit_payload
	// ride as the note; the O+ pending card reads it back.
	if agent := strings.TrimSpace(p.AgentID); agent != "" {
		if editPayload == nil {
			editPayload = make(map[string]any, 1)
		}
		editPayload[AgentIDEditPayloadKey] = agent
	}
	return &HITLDecision{
		EventID:        p.EventID,
		TenantID:       p.TenantID,
		DecisionID:     p.DecisionID,
		RunID:          p.RunID,
		OperatorGcid:   "", // no operator on a pending gate
		AssigneeGcid:   nil,
		Decision:       HitlPending,
		AutonomyLevel:  autonomy,
		EditPayload:    editPayload,
		Note:           note,
		LifecycleStage: stage,
		DecidedAt:      eventTime(p.OccurredAt), // gate-raised timestamp (waiting_since)
	}, nil
}

// canonicaliseAssigneeGcid returns nil for nil-in / blank-after-trim, the
// trimmed value otherwise. Rejecting blank strings prevents synthetic
// placeholders ("", " ") from masquerading as NULL.
func canonicaliseAssigneeGcid(in *string) (*string, error) {
	if in == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*in)
	if trimmed == "" {
		return nil, fmt.Errorf("assignee_gcid: blank string is not a valid GCID — pass nil for unassigned")
	}
	return &trimmed, nil
}

// HITLDecision self-claim sentinel errors. Callers (HTTP handler, BFF) inspect
// these via errors.Is to map domain failures to HTTP status codes:
//
//	ErrHITLAlreadyClaimed  → 409 Conflict (race: another reviewer claimed first)
//	ErrHITLNotAssignee     → 403 Forbidden (Release only by current assignee)
//	ErrHITLTerminal        → 409 Conflict (verdict already recorded; no claim allowed)
var (
	ErrHITLAlreadyClaimed = errors.New("evidence: hitl decision already claimed")
	ErrHITLNotAssignee    = errors.New("evidence: release rejected — caller is not the current assignee")
	ErrHITLTerminal       = errors.New("evidence: hitl decision is terminal (verdict recorded)")
)

// Claim sets AssigneeGcid on a pending HITLDecision when no one currently
// holds it (or idempotently when the same reviewer re-claims). Per the
// self-claim model documented in migration 0008 + the HITLDecision godoc.
//
// Invariants enforced:
//
//   - operatorGcid MUST be non-blank-after-trim. Blank inputs return an error;
//     callers MUST NOT pass synthetic placeholders ("", " ") for "unassigned".
//   - The row MUST be in the pending verdict state. A row carrying a canonical
//     HitlVerdict (approve|reject|edit) is terminal — claim is rejected with
//     ErrHITLTerminal because the gate is already decided.
//   - If the row is already claimed by a DIFFERENT reviewer, returns
//     ErrHITLAlreadyClaimed (HTTP 409). If by the SAME reviewer the call is
//     idempotent (no-op return nil) so flaky-network retries do not 409 the UX.
//
// The `now` clock is accepted for future timestamp wiring (claim history /
// updated_at) — currently the migration 0008 schema has no updated_at column
// so the value is not persisted but the signature is forward-compatible.
func (d *HITLDecision) Claim(operatorGcid string, now time.Time) error {
	if d == nil {
		return errors.New("evidence: nil HITLDecision")
	}
	trimmed := strings.TrimSpace(operatorGcid)
	if trimmed == "" {
		return fmt.Errorf("evidence: operator_gcid is required (blank string is not a valid GCID)")
	}
	if d.terminalVerdict() {
		return ErrHITLTerminal
	}
	if d.AssigneeGcid != nil && *d.AssigneeGcid != "" {
		if *d.AssigneeGcid == trimmed {
			return nil // idempotent re-claim by the current assignee
		}
		return ErrHITLAlreadyClaimed
	}
	d.AssigneeGcid = &trimmed
	_ = now // reserved for future claim-history wiring (see migration 0008 note)
	return nil
}

// Release clears AssigneeGcid on a pending HITLDecision. Only the current
// assignee may release (admin-override path is a documented M12 follow-up;
// the simpler assignee-only contract ships first).
//
// Invariants enforced:
//
//   - operatorGcid MUST be non-blank.
//   - The row MUST currently be claimed (AssigneeGcid != nil).
//   - operatorGcid MUST match the current AssigneeGcid; mismatch returns
//     ErrHITLNotAssignee (HTTP 403).
//   - Release on a terminal (verdict-recorded) row returns ErrHITLTerminal —
//     the assignee history on a decided row is read-only.
func (d *HITLDecision) Release(operatorGcid string, now time.Time) error {
	if d == nil {
		return errors.New("evidence: nil HITLDecision")
	}
	trimmed := strings.TrimSpace(operatorGcid)
	if trimmed == "" {
		return fmt.Errorf("evidence: operator_gcid is required (blank string is not a valid GCID)")
	}
	if d.terminalVerdict() {
		return ErrHITLTerminal
	}
	if d.AssigneeGcid == nil || *d.AssigneeGcid == "" {
		return fmt.Errorf("evidence: cannot release unassigned hitl decision")
	}
	if *d.AssigneeGcid != trimmed {
		return ErrHITLNotAssignee
	}
	d.AssigneeGcid = nil
	_ = now // reserved for future release-history wiring
	return nil
}

// terminalVerdict reports whether the decision carries a canonical recorded
// verdict (approve|reject|edit). Pending rows carry an empty / "pending"
// HitlVerdict that is NOT terminal.
func (d *HITLDecision) terminalVerdict() bool {
	return d.Decision.Valid()
}

// Approve records an APPROVE verdict on a pending HITLDecision. Mirrors the
// validation style of Claim/Release.
//
// Invariants enforced:
//
//   - operatorGcid MUST be non-blank-after-trim (callers MUST NOT pass a
//     synthetic placeholder); blank returns an error.
//   - The row MUST be in the pending verdict state. A row that already carries
//     a canonical HitlVerdict (approve|reject|edit) is terminal — Approve is
//     rejected with ErrHITLTerminal (the verdict on the append-only ledger is
//     immutable; re-deciding requires a fresh gate).
//
// On success the aggregate is mutated to carry the verdict: Decision=approve,
// OperatorGcid=operator, DecidedAt=now, and the optional note stored on the
// Note field + mirrored into EditPayload[NoteEditPayloadKey]. The caller then
// persists via Repository.RecordHITLVerdict which APPENDS a new
// hitl_decision_log row (the verdict columns are append-only at the DB layer
// per migration 0009 — they cannot be UPDATEd in place like assignee_gcid).
func (d *HITLDecision) Approve(operatorGcid string, note string, now time.Time) error {
	return d.recordVerdict(HitlApprove, operatorGcid, note, now)
}

// Reject records a REJECT verdict on a pending HITLDecision. Same contract as
// Approve — see its godoc.
func (d *HITLDecision) Reject(operatorGcid string, note string, now time.Time) error {
	return d.recordVerdict(HitlReject, operatorGcid, note, now)
}

// noteFromEditPayload returns the operator note stored under
// NoteEditPayloadKey, or "" when absent / non-string. Used by repository
// loaders to rehydrate the Note field from the edit_payload JSONB column.
func noteFromEditPayload(m map[string]any) string {
	if m == nil {
		return ""
	}
	if v, ok := m[NoteEditPayloadKey].(string); ok {
		return v
	}
	return ""
}

// recordVerdict is the shared Approve/Reject body. Validates the operator GCID
// + terminal-state guard, then mutates the aggregate to carry the verdict.
func (d *HITLDecision) recordVerdict(verdict HitlVerdict, operatorGcid string, note string, now time.Time) error {
	if d == nil {
		return errors.New("evidence: nil HITLDecision")
	}
	trimmed := strings.TrimSpace(operatorGcid)
	if trimmed == "" {
		return fmt.Errorf("evidence: operator_gcid is required (blank string is not a valid GCID)")
	}
	if d.terminalVerdict() {
		return ErrHITLTerminal
	}
	d.Decision = verdict
	d.OperatorGcid = trimmed
	d.DecidedAt = now.UTC()
	trimmedNote := strings.TrimSpace(note)
	d.Note = trimmedNote
	if trimmedNote != "" {
		if d.EditPayload == nil {
			d.EditPayload = make(map[string]any, 1)
		}
		d.EditPayload[NoteEditPayloadKey] = trimmedNote
	}
	return nil
}

// =============================================================================
// PolicyViolation (Tier 3 D9 ContentPolicyViolationLog)
// =============================================================================

// PolicyViolation records a runtime policy violation detected by the
// Guardrail Service.
type PolicyViolation struct {
	EventID        string         `json:"event_id"`
	TenantID       string         `json:"tenant_id"`
	AgentID        string         `json:"agent_id"`
	PolicyName     string         `json:"policy_name"`
	Severity       string         `json:"severity"`
	Detector       string         `json:"detector"`
	Payload        map[string]any `json:"payload"`
	LifecycleStage LifecycleStage `json:"lifecycle_stage"`
	DetectedAt     time.Time      `json:"detected_at"`
}

// PolicyViolationParams is the constructor input.
type PolicyViolationParams struct {
	EventID        string
	TenantID       string
	AgentID        string
	PolicyName     string
	Severity       string
	Detector       string
	Payload        map[string]any
	LifecycleStage LifecycleStage

	// OccurredAt is when the underlying EVENT happened, from the producer's
	// envelope. Zero falls back to now (see eventTime).
	OccurredAt time.Time
}

// NewPolicyViolation constructs a policy-violation row.
func NewPolicyViolation(p PolicyViolationParams) (*PolicyViolation, error) {
	for k, v := range map[string]string{
		"event_id":    p.EventID,
		"tenant_id":   p.TenantID,
		"agent_id":    p.AgentID,
		"policy_name": p.PolicyName,
		"severity":    p.Severity,
		"detector":    p.Detector,
	} {
		if err := requireNonBlank(k, v); err != nil {
			return nil, err
		}
	}
	stage := defaultLifecycle(p.LifecycleStage, LifecycleRuntime)
	if !stage.Valid() {
		return nil, fmt.Errorf("invalid lifecycle_stage: %q", p.LifecycleStage)
	}
	return &PolicyViolation{
		EventID:        p.EventID,
		TenantID:       p.TenantID,
		AgentID:        p.AgentID,
		PolicyName:     p.PolicyName,
		Severity:       p.Severity,
		Detector:       p.Detector,
		Payload:        copyMap(p.Payload),
		LifecycleStage: stage,
		DetectedAt:     eventTime(p.OccurredAt),
	}, nil
}

// =============================================================================
// Repository port + InMemoryRepository
// =============================================================================

// QueryFilter is the read-side filter for evidence queries.
type QueryFilter struct {
	TenantID       string
	LifecycleStage LifecycleStage // empty = no filter
	AgentID        string         // empty = no filter (where applicable)
	Audience       Audience       // for DecisionExplanation queries
	From, To       *time.Time
	Limit, Offset  int
}

// ErrNotFound is the canonical sentinel for a missing row.
var ErrNotFound = errors.New("evidence: not found")

// Repository is the IMDA evidence persistence port.
type Repository interface {
	// D1
	AppendAccountability(ctx context.Context, e *AccountabilityEvidence) error
	QueryAccountability(ctx context.Context, f QueryFilter) ([]*AccountabilityEvidence, error)

	// D2
	AppendModelCard(ctx context.Context, c *ModelCard) error
	QueryModelCards(ctx context.Context, f QueryFilter) ([]*ModelCard, error)

	AppendDataCard(ctx context.Context, d *DataCard) error
	QueryDataCards(ctx context.Context, f QueryFilter) ([]*DataCard, error)

	AppendDecisionExplanation(ctx context.Context, e *DecisionExplanation) error
	QueryDecisionExplanation(ctx context.Context, f QueryFilter) ([]*DecisionExplanation, error)
	GetDecisionExplanationByDecisionID(ctx context.Context, tenantID, decisionID string, audience Audience) ([]*DecisionExplanation, error)

	// D3
	AppendRedTeamRun(ctx context.Context, r *RedTeamRun) error
	QueryRedTeamRuns(ctx context.Context, f QueryFilter) ([]*RedTeamRun, error)

	AppendEvalRun(ctx context.Context, r *EvalRun) error
	QueryEvalRuns(ctx context.Context, f QueryFilter) ([]*EvalRun, error)

	AppendCostAnomaly(ctx context.Context, a *CostAnomaly) error
	QueryCostAnomalies(ctx context.Context, f QueryFilter) ([]*CostAnomaly, error)

	UpsertCircuitBreaker(ctx context.Context, c *CircuitBreaker) error
	QueryCircuitBreakers(ctx context.Context, f QueryFilter) ([]*CircuitBreaker, error)

	UpsertQuarantine(ctx context.Context, q *Quarantine) error
	QueryQuarantines(ctx context.Context, f QueryFilter) ([]*Quarantine, error)

	// D4
	AppendBiasTestRun(ctx context.Context, r *BiasTestRun) error
	QueryBiasTestRuns(ctx context.Context, f QueryFilter) ([]*BiasTestRun, error)

	AppendHITLDecision(ctx context.Context, d *HITLDecision) error
	QueryHITLDecisions(ctx context.Context, f QueryFilter) ([]*HITLDecision, error)

	// LoadHITLDecision returns the row identified by (tenantID, decisionID)
	// or ErrNotFound. Used by the POST /api/hitl/decisions/{id}/claim
	// endpoint to load the aggregate before invoking Claim()/Release().
	// MUST be tenant-scoped — cross-tenant access returns ErrNotFound (no
	// existence-leak across tenants).
	LoadHITLDecision(ctx context.Context, tenantID, decisionID string) (*HITLDecision, error)

	// UpdateAssigneeGcid persists a self-claim or release. When assigneeGcid
	// is non-nil the row's assignee_gcid column is set; nil clears it
	// (release). The `now` clock is accepted for forward-compatible
	// updated_at wiring (no-op against migration 0008 schema which has no
	// updated_at column on hitl_decision_log).
	//
	// Implementations SHOULD use optimistic concurrency (e.g. WHERE
	// assignee_gcid = expected) to guard against the claim race; the in-
	// memory implementation is single-mutex serialised.
	//
	// Returns ErrNotFound when no row matches (tenantID, decisionID).
	UpdateAssigneeGcid(ctx context.Context, tenantID, decisionID string, assigneeGcid *string, now time.Time) error

	// RecordHITLVerdict persists an operator's approve/reject verdict for a
	// HITL gate. Unlike UpdateAssigneeGcid (an in-place mutation of the
	// ephemeral assignee column), the verdict columns of hitl_decision_log
	// are APPEND-ONLY at the DB layer (migration 0009's trigger rejects any
	// in-place change to decision/operator_gcid/decided_at). Implementations
	// therefore APPEND a fresh hitl_decision_log row carrying the verdict
	// (a new event_id, the same decision_id/run_id/tenant_id, the verdict +
	// operator_gcid + decided_at, and the optional note folded into the
	// edit_payload JSONB under NoteEditPayloadKey).
	//
	// The supplied src aggregate provides the immutable context fields
	// (DecisionID, RunID, AutonomyLevel, LifecycleStage, AssigneeGcid). It
	// MUST already carry the verdict (Decision/OperatorGcid/DecidedAt set by
	// HITLDecision.Approve/Reject). Re-delivery of the same verdict event_id
	// is idempotent at the unique-constraint layer.
	RecordHITLVerdict(ctx context.Context, src *HITLDecision) error

	// Policy violation
	AppendPolicyViolation(ctx context.Context, v *PolicyViolation) error
	QueryPolicyViolations(ctx context.Context, f QueryFilter) ([]*PolicyViolation, error)
}

// InMemoryRepository is the dev/test implementation of Repository. Idempotent
// on EventID per row.
type InMemoryRepository struct {
	mu sync.RWMutex

	accountabilities map[string]*AccountabilityEvidence
	modelCards       map[string]*ModelCard
	dataCards        map[string]*DataCard
	decisionExpls    map[string]*DecisionExplanation
	redTeamRuns      map[string]*RedTeamRun
	evalRuns         map[string]*EvalRun
	costAnomalies    map[string]*CostAnomaly
	circuitBreakers  map[string]*CircuitBreaker // key=tenant|agent
	quarantines      map[string]*Quarantine     // key=tenant|agent
	biasTestRuns     map[string]*BiasTestRun
	hitlDecisions    map[string]*HITLDecision
	policyViolations map[string]*PolicyViolation
}

// NewInMemoryRepository constructs an empty in-memory repository.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		accountabilities: make(map[string]*AccountabilityEvidence),
		modelCards:       make(map[string]*ModelCard),
		dataCards:        make(map[string]*DataCard),
		decisionExpls:    make(map[string]*DecisionExplanation),
		redTeamRuns:      make(map[string]*RedTeamRun),
		evalRuns:         make(map[string]*EvalRun),
		costAnomalies:    make(map[string]*CostAnomaly),
		circuitBreakers:  make(map[string]*CircuitBreaker),
		quarantines:      make(map[string]*Quarantine),
		biasTestRuns:     make(map[string]*BiasTestRun),
		hitlDecisions:    make(map[string]*HITLDecision),
		policyViolations: make(map[string]*PolicyViolation),
	}
}

// -----------------------------------------------------------------------------
// D1
// -----------------------------------------------------------------------------

func (m *InMemoryRepository) AppendAccountability(_ context.Context, e *AccountabilityEvidence) error {
	if e == nil {
		return errors.New("nil evidence")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.accountabilities[e.EventID]; ok {
		return nil // idempotent
	}
	clone := *e
	clone.Provenance = copyMap(e.Provenance)
	m.accountabilities[e.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryAccountability(_ context.Context, f QueryFilter) ([]*AccountabilityEvidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*AccountabilityEvidence, 0)
	for _, e := range m.accountabilities {
		if !matchTenant(f.TenantID, e.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, e.LifecycleStage) {
			continue
		}
		if f.AgentID != "" && e.AgentID != f.AgentID {
			continue
		}
		if !matchTimeRange(f.From, f.To, e.RecordedAt) {
			continue
		}
		clone := *e
		clone.Provenance = copyMap(e.Provenance)
		out = append(out, &clone)
	}
	sortAccountability(out)
	return paginate(out, f.Limit, f.Offset), nil
}

// -----------------------------------------------------------------------------
// D2
// -----------------------------------------------------------------------------

func (m *InMemoryRepository) AppendModelCard(_ context.Context, c *ModelCard) error {
	if c == nil {
		return errors.New("nil model card")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.modelCards[c.EventID]; ok {
		return nil
	}
	clone := *c
	clone.FairnessAttestations = copyMap(c.FairnessAttestations)
	m.modelCards[c.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryModelCards(_ context.Context, f QueryFilter) ([]*ModelCard, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*ModelCard, 0)
	for _, c := range m.modelCards {
		if !matchTenant(f.TenantID, c.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, c.LifecycleStage) {
			continue
		}
		clone := *c
		clone.FairnessAttestations = copyMap(c.FairnessAttestations)
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RegisteredAt.After(out[j].RegisteredAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

func (m *InMemoryRepository) AppendDataCard(_ context.Context, d *DataCard) error {
	if d == nil {
		return errors.New("nil data card")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.dataCards[d.EventID]; ok {
		return nil
	}
	clone := *d
	clone.Schema = copyMap(d.Schema)
	m.dataCards[d.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryDataCards(_ context.Context, f QueryFilter) ([]*DataCard, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*DataCard, 0)
	for _, d := range m.dataCards {
		if !matchTenant(f.TenantID, d.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, d.LifecycleStage) {
			continue
		}
		clone := *d
		clone.Schema = copyMap(d.Schema)
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RegisteredAt.After(out[j].RegisteredAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

func (m *InMemoryRepository) AppendDecisionExplanation(_ context.Context, e *DecisionExplanation) error {
	if e == nil {
		return errors.New("nil explanation")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.decisionExpls[e.EventID]; ok {
		return nil
	}
	clone := *e
	m.decisionExpls[e.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryDecisionExplanation(_ context.Context, f QueryFilter) ([]*DecisionExplanation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*DecisionExplanation, 0)
	for _, e := range m.decisionExpls {
		if !matchTenant(f.TenantID, e.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, e.LifecycleStage) {
			continue
		}
		if f.Audience != "" && e.Audience != f.Audience {
			continue
		}
		clone := *e
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].GeneratedAt.After(out[j].GeneratedAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

// GetDecisionExplanationByDecisionID returns explanations for a single decision
// id, role-filtered by audience. Mirrors the Three-Audience SQL views.
func (m *InMemoryRepository) GetDecisionExplanationByDecisionID(_ context.Context, tenantID, decisionID string, audience Audience) ([]*DecisionExplanation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*DecisionExplanation, 0)
	for _, e := range m.decisionExpls {
		if e.TenantID != tenantID || e.DecisionID != decisionID {
			continue
		}
		if audience != "" && !audienceCanSee(audience, e.Audience) {
			continue
		}
		clone := *e
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].GeneratedAt.After(out[j].GeneratedAt)
	})
	return out, nil
}

// audienceCanSee mirrors the SQL view filter rules:
//   - learner sees only learner rows
//   - instructor_admin sees instructor_admin + learner rows
//   - auditor sees all rows
func audienceCanSee(viewer, row Audience) bool {
	switch viewer {
	case AudienceLearner:
		return row == AudienceLearner
	case AudienceInstructorAdmin:
		return row == AudienceInstructorAdmin || row == AudienceLearner
	case AudienceAuditor:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// D3
// -----------------------------------------------------------------------------

func (m *InMemoryRepository) AppendRedTeamRun(_ context.Context, r *RedTeamRun) error {
	if r == nil {
		return errors.New("nil red-team run")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.redTeamRuns[r.EventID]; ok {
		return nil
	}
	clone := *r
	clone.Scenario = copyMap(r.Scenario)
	clone.Findings = copyMap(r.Findings)
	m.redTeamRuns[r.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryRedTeamRuns(_ context.Context, f QueryFilter) ([]*RedTeamRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*RedTeamRun, 0)
	for _, r := range m.redTeamRuns {
		if !matchTenant(f.TenantID, r.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, r.LifecycleStage) {
			continue
		}
		if f.AgentID != "" && r.AgentID != f.AgentID {
			continue
		}
		clone := *r
		clone.Scenario = copyMap(r.Scenario)
		clone.Findings = copyMap(r.Findings)
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RunAt.After(out[j].RunAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

func (m *InMemoryRepository) AppendEvalRun(_ context.Context, r *EvalRun) error {
	if r == nil {
		return errors.New("nil eval run")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.evalRuns[r.EventID]; ok {
		return nil
	}
	clone := *r
	m.evalRuns[r.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryEvalRuns(_ context.Context, f QueryFilter) ([]*EvalRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*EvalRun, 0)
	for _, r := range m.evalRuns {
		if !matchTenant(f.TenantID, r.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, r.LifecycleStage) {
			continue
		}
		if f.AgentID != "" && r.AgentID != f.AgentID {
			continue
		}
		clone := *r
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RunAt.After(out[j].RunAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

func (m *InMemoryRepository) AppendCostAnomaly(_ context.Context, a *CostAnomaly) error {
	if a == nil {
		return errors.New("nil cost anomaly")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.costAnomalies[a.EventID]; ok {
		return nil
	}
	clone := *a
	m.costAnomalies[a.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryCostAnomalies(_ context.Context, f QueryFilter) ([]*CostAnomaly, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*CostAnomaly, 0)
	for _, a := range m.costAnomalies {
		if !matchTenant(f.TenantID, a.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, a.LifecycleStage) {
			continue
		}
		if f.AgentID != "" && a.AgentID != f.AgentID {
			continue
		}
		clone := *a
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RecordedAt.After(out[j].RecordedAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

func (m *InMemoryRepository) UpsertCircuitBreaker(_ context.Context, c *CircuitBreaker) error {
	if c == nil {
		return errors.New("nil circuit breaker")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := c.tenantID + "|" + c.agentID
	m.circuitBreakers[key] = c
	return nil
}

func (m *InMemoryRepository) QueryCircuitBreakers(_ context.Context, f QueryFilter) ([]*CircuitBreaker, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*CircuitBreaker, 0)
	for _, c := range m.circuitBreakers {
		if !matchTenant(f.TenantID, c.tenantID) {
			continue
		}
		if f.AgentID != "" && c.agentID != f.AgentID {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func (m *InMemoryRepository) UpsertQuarantine(_ context.Context, q *Quarantine) error {
	if q == nil {
		return errors.New("nil quarantine")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := q.TenantID + "|" + q.AgentID
	m.quarantines[key] = q
	return nil
}

func (m *InMemoryRepository) QueryQuarantines(_ context.Context, f QueryFilter) ([]*Quarantine, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Quarantine, 0)
	for _, q := range m.quarantines {
		if !matchTenant(f.TenantID, q.TenantID) {
			continue
		}
		if f.AgentID != "" && q.AgentID != f.AgentID {
			continue
		}
		out = append(out, q)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// D4
// -----------------------------------------------------------------------------

func (m *InMemoryRepository) AppendBiasTestRun(_ context.Context, r *BiasTestRun) error {
	if r == nil {
		return errors.New("nil bias test run")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.biasTestRuns[r.EventID]; ok {
		return nil
	}
	clone := *r
	m.biasTestRuns[r.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryBiasTestRuns(_ context.Context, f QueryFilter) ([]*BiasTestRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*BiasTestRun, 0)
	for _, r := range m.biasTestRuns {
		if !matchTenant(f.TenantID, r.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, r.LifecycleStage) {
			continue
		}
		if f.AgentID != "" && r.AgentID != f.AgentID {
			continue
		}
		clone := *r
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RunAt.After(out[j].RunAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

func (m *InMemoryRepository) AppendHITLDecision(_ context.Context, d *HITLDecision) error {
	if d == nil {
		return errors.New("nil hitl decision")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hitlDecisions[d.EventID]; ok {
		return nil
	}
	clone := *d
	clone.EditPayload = copyMap(d.EditPayload)
	m.hitlDecisions[d.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryHITLDecisions(_ context.Context, f QueryFilter) ([]*HITLDecision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*HITLDecision, 0)
	for _, d := range m.hitlDecisions {
		if !matchTenant(f.TenantID, d.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, d.LifecycleStage) {
			continue
		}
		clone := *d
		clone.EditPayload = copyMap(d.EditPayload)
		if clone.Note == "" {
			clone.Note = noteFromEditPayload(clone.EditPayload)
		}
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].DecidedAt.After(out[j].DecidedAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

// LoadHITLDecision returns a deep clone of the row identified by
// (tenantID, decisionID) or ErrNotFound. Tenant-scoped — cross-tenant
// lookup returns ErrNotFound rather than leaking existence across tenants.
func (m *InMemoryRepository) LoadHITLDecision(_ context.Context, tenantID, decisionID string) (*HITLDecision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// ADR-170 append-to-resolve leaves a pending row plus (once a verdict is
	// recorded) a resolved row sharing the same decision_id. Return the CURRENT
	// authoritative state: a terminal (resolved) row wins over a pending one,
	// and among same-terminality rows the later DecidedAt wins. Matches the pg
	// adapter's `ORDER BY decided_at DESC NULLS LAST`. Map iteration order is
	// non-deterministic, so an explicit selection is required here.
	var best *HITLDecision
	for _, d := range m.hitlDecisions {
		if d.TenantID != tenantID || d.DecisionID != decisionID {
			continue
		}
		if best == nil || moreCurrentHITL(d, best) {
			best = d
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	clone := *best
	clone.EditPayload = copyMap(best.EditPayload)
	if clone.Note == "" {
		clone.Note = noteFromEditPayload(clone.EditPayload)
	}
	return &clone, nil
}

// moreCurrentHITL reports whether row a represents a more-current state of a
// HITL decision than row b (both assumed to share tenant + decision_id): a
// terminal verdict supersedes a pending row, and among same-terminality rows
// the later DecidedAt wins.
func moreCurrentHITL(a, b *HITLDecision) bool {
	aTerm, bTerm := !a.Decision.IsPending(), !b.Decision.IsPending()
	if aTerm != bTerm {
		return aTerm
	}
	return a.DecidedAt.After(b.DecidedAt)
}

// UpdateAssigneeGcid sets (or clears, when assigneeGcid is nil) the
// AssigneeGcid field of the matching row. The `now` argument is reserved
// for forward-compatible updated_at wiring (no-op against migration 0008
// schema which has no updated_at column). Returns ErrNotFound when no row
// matches (tenantID, decisionID).
//
// Concurrency: serialised on the same mutex as AppendHITLDecision so
// concurrent claims race-safe within the in-memory implementation. The pg
// adapter uses optimistic concurrency at the SQL layer (see UpdateAssigneeGcid).
func (m *InMemoryRepository) UpdateAssigneeGcid(_ context.Context, tenantID, decisionID string, assigneeGcid *string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.hitlDecisions {
		if d.TenantID == tenantID && d.DecisionID == decisionID {
			if assigneeGcid == nil {
				d.AssigneeGcid = nil
			} else {
				trimmed := strings.TrimSpace(*assigneeGcid)
				if trimmed == "" {
					return fmt.Errorf("evidence: assignee_gcid blank-after-trim — pass nil to clear")
				}
				d.AssigneeGcid = &trimmed
			}
			_ = now // reserved for updated_at wiring
			return nil
		}
	}
	return ErrNotFound
}

// RecordHITLVerdict appends a fresh verdict row keyed on src.EventID. Mirrors
// AppendHITLDecision's idempotency (no-op on duplicate EventID) — the verdict
// is a NEW append-only row, NOT an in-place mutation of the pending row.
func (m *InMemoryRepository) RecordHITLVerdict(_ context.Context, src *HITLDecision) error {
	if src == nil {
		return errors.New("nil hitl verdict")
	}
	if strings.TrimSpace(src.EventID) == "" {
		return errors.New("evidence: RecordHITLVerdict: event_id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hitlDecisions[src.EventID]; ok {
		return nil // idempotent
	}
	clone := *src
	clone.EditPayload = copyMap(src.EditPayload)
	m.hitlDecisions[src.EventID] = &clone
	return nil
}

// -----------------------------------------------------------------------------
// PolicyViolation
// -----------------------------------------------------------------------------

func (m *InMemoryRepository) AppendPolicyViolation(_ context.Context, v *PolicyViolation) error {
	if v == nil {
		return errors.New("nil policy violation")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policyViolations[v.EventID]; ok {
		return nil
	}
	clone := *v
	clone.Payload = copyMap(v.Payload)
	m.policyViolations[v.EventID] = &clone
	return nil
}

func (m *InMemoryRepository) QueryPolicyViolations(_ context.Context, f QueryFilter) ([]*PolicyViolation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*PolicyViolation, 0)
	for _, v := range m.policyViolations {
		if !matchTenant(f.TenantID, v.TenantID) {
			continue
		}
		if !matchLifecycle(f.LifecycleStage, v.LifecycleStage) {
			continue
		}
		if f.AgentID != "" && v.AgentID != f.AgentID {
			continue
		}
		clone := *v
		clone.Payload = copyMap(v.Payload)
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].DetectedAt.After(out[j].DetectedAt)
	})
	return paginate(out, f.Limit, f.Offset), nil
}

// =============================================================================
// Helpers
// =============================================================================

func requireNonBlank(field, v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func defaultLifecycle(in, fallback LifecycleStage) LifecycleStage {
	if in == "" {
		return fallback
	}
	return in
}

func copyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func matchTenant(filter, row string) bool {
	if filter == "" {
		return true
	}
	return filter == row
}

func matchLifecycle(filter, row LifecycleStage) bool {
	if filter == "" {
		return true
	}
	return filter == row
}

func matchTimeRange(from, to *time.Time, t time.Time) bool {
	if from != nil && t.Before(*from) {
		return false
	}
	if to != nil && t.After(*to) {
		return false
	}
	return true
}

func paginate[T any](in []*T, limit, offset int) []*T {
	if offset >= len(in) {
		return nil
	}
	if offset > 0 {
		in = in[offset:]
	}
	if limit > 0 && len(in) > limit {
		in = in[:limit]
	}
	return in
}

func sortAccountability(out []*AccountabilityEvidence) {
	sort.Slice(out, func(i, j int) bool {
		return out[i].RecordedAt.After(out[j].RecordedAt)
	})
}
