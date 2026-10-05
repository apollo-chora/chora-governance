// Package evidence — RED tests for the IMDA D1-D4 evidence aggregates.
//
// Per CLAUDE.md §1 (IMDA NorthStar) + ADR-141 canonical labels +
// audit-platform-fillgaps.md §3.3 + §5 (all 11 D1-D4 evidence tables missing),
// these tests define the expected behaviour of the 11 net-new evidence
// aggregates BEFORE implementation. RED first per .claude/rules/development-execution.md.
//
// Aggregates under test (constructors + invariants + idempotency):
//
//	D1 accountability_evidence
//	D2 model_card_registry, data_card_registry, decision_explanation
//	D3 red_team_runs, eval_runs, cost_anomalies, circuit_breaker_state, quarantine_state
//	D4 bias_test_runs, hitl_decision_log
//	+  policy_violation_log (Tier 3 D9 ContentPolicyViolationLog)
package evidence_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

// -----------------------------------------------------------------------------
// LifecycleStage — closed enum per envelope.proto field 15
// -----------------------------------------------------------------------------

func TestLifecycleStage_Valid(t *testing.T) {
	for _, s := range []evidence.LifecycleStage{
		evidence.LifecycleCIPreMerge,
		evidence.LifecyclePreDeploy,
		evidence.LifecycleRuntime,
		evidence.LifecyclePostDeploy,
	} {
		if !s.Valid() {
			t.Errorf("expected %q valid", s)
		}
	}
}

func TestLifecycleStage_Invalid(t *testing.T) {
	for _, s := range []evidence.LifecycleStage{"", "production", "deploy", "PRE_DEPLOY"} {
		if s.Valid() {
			t.Errorf("expected %q invalid", s)
		}
	}
}

// -----------------------------------------------------------------------------
// Audience — Three-Audience explainability per Tier 4 D16
// -----------------------------------------------------------------------------

func TestAudience_Valid(t *testing.T) {
	for _, a := range []evidence.Audience{
		evidence.AudienceLearner,
		evidence.AudienceInstructorAdmin,
		evidence.AudienceAuditor,
	} {
		if !a.Valid() {
			t.Errorf("expected %q valid", a)
		}
	}
}

func TestAudience_Invalid(t *testing.T) {
	for _, a := range []evidence.Audience{"", "admin", "regulator", "AUDITOR"} {
		if a.Valid() {
			t.Errorf("expected %q invalid", a)
		}
	}
}

// -----------------------------------------------------------------------------
// AutonomyLevel — Level 3 (out-of-band autonomous) PROHIBITED per ADR-141
// -----------------------------------------------------------------------------

func TestAutonomyLevel_Valid(t *testing.T) {
	for _, l := range []evidence.AutonomyLevel{
		evidence.AutonomyHootl,
		evidence.AutonomyHotl,
		evidence.AutonomyHitlL0,
		evidence.AutonomyHitlL1,
		evidence.AutonomyHitlL2,
	} {
		if !l.Valid() {
			t.Errorf("expected %q valid", l)
		}
	}
}

func TestAutonomyLevel_RejectsLevel3(t *testing.T) {
	bad := evidence.AutonomyLevel("hitl_l3")
	if bad.Valid() {
		t.Error("Level 3 (out-of-band autonomous) MUST be rejected per ADR-141")
	}
	bad2 := evidence.AutonomyLevel("level_3")
	if bad2.Valid() {
		t.Error("Level 3 alias MUST be rejected per ADR-141")
	}
}

// -----------------------------------------------------------------------------
// HITLVerdict
// -----------------------------------------------------------------------------

func TestHitlVerdict_Valid(t *testing.T) {
	for _, v := range []evidence.HitlVerdict{
		evidence.HitlApprove, evidence.HitlReject, evidence.HitlEdit,
	} {
		if !v.Valid() {
			t.Errorf("expected %q valid", v)
		}
	}
}

// -----------------------------------------------------------------------------
// CircuitBreakerState — closed | half_open | open
// -----------------------------------------------------------------------------

func TestCircuitBreakerState_Valid(t *testing.T) {
	for _, s := range []evidence.CircuitBreakerState{
		evidence.CircuitClosed, evidence.CircuitHalfOpen, evidence.CircuitOpen,
	} {
		if !s.Valid() {
			t.Errorf("expected %q valid", s)
		}
	}
}

// -----------------------------------------------------------------------------
// D1 accountability_evidence
// -----------------------------------------------------------------------------

func TestNewAccountabilityEvidence_Happy(t *testing.T) {
	e, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID:        "11111111-1111-1111-1111-111111111111",
		TenantID:       "22222222-2222-2222-2222-222222222222",
		AgentID:        "agent-router-v1",
		OwnerGcid:      "33333333-3333-3333-3333-333333333333",
		DecisionID:     "dec-abc",
		DecisionType:   "route_to_gemini",
		Provenance:     map[string]any{"reason": "intent=qna"},
		LifecycleStage: evidence.LifecycleRuntime,
	})
	if err != nil {
		t.Fatalf("err=%v want nil", err)
	}
	if e.EvidenceHash == "" {
		t.Error("EvidenceHash must be populated")
	}
	if e.LifecycleStage != evidence.LifecycleRuntime {
		t.Errorf("LifecycleStage=%v want runtime", e.LifecycleStage)
	}
	if e.RecordedAt.IsZero() {
		t.Error("RecordedAt must be populated")
	}
}

func TestNewAccountabilityEvidence_RequiredFields(t *testing.T) {
	cases := []struct {
		name string
		p    evidence.AccountabilityParams
	}{
		{"missing event_id", evidence.AccountabilityParams{TenantID: "t", AgentID: "a", OwnerGcid: "o", DecisionID: "d", DecisionType: "x"}},
		{"missing tenant_id", evidence.AccountabilityParams{EventID: "e", AgentID: "a", OwnerGcid: "o", DecisionID: "d", DecisionType: "x"}},
		{"missing agent_id", evidence.AccountabilityParams{EventID: "e", TenantID: "t", OwnerGcid: "o", DecisionID: "d", DecisionType: "x"}},
		{"missing owner_gcid", evidence.AccountabilityParams{EventID: "e", TenantID: "t", AgentID: "a", DecisionID: "d", DecisionType: "x"}},
		{"missing decision_id", evidence.AccountabilityParams{EventID: "e", TenantID: "t", AgentID: "a", OwnerGcid: "o", DecisionType: "x"}},
		{"missing decision_type", evidence.AccountabilityParams{EventID: "e", TenantID: "t", AgentID: "a", OwnerGcid: "o", DecisionID: "d"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := evidence.NewAccountabilityEvidence(tc.p); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestNewAccountabilityEvidence_DefaultsLifecycleToRuntime(t *testing.T) {
	e, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID:      "e1",
		TenantID:     "t1",
		AgentID:      "a1",
		OwnerGcid:    "o1",
		DecisionID:   "d1",
		DecisionType: "x",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if e.LifecycleStage != evidence.LifecycleRuntime {
		t.Errorf("LifecycleStage=%v want runtime (default)", e.LifecycleStage)
	}
}

func TestNewAccountabilityEvidence_RejectsInvalidLifecycle(t *testing.T) {
	_, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID:        "e1",
		TenantID:       "t1",
		AgentID:        "a1",
		OwnerGcid:      "o1",
		DecisionID:     "d1",
		DecisionType:   "x",
		LifecycleStage: "production",
	})
	if err == nil {
		t.Error("expected invalid-lifecycle error")
	}
}

// -----------------------------------------------------------------------------
// D2 model_card_registry
// -----------------------------------------------------------------------------

func TestNewModelCard_Happy(t *testing.T) {
	c, err := evidence.NewModelCard(evidence.ModelCardParams{
		EventID:             "e",
		TenantID:            "t",
		ModelID:             "gemini-2.5-flash",
		ModelVersion:        "v1",
		CardMD:              "# Model Card",
		TrainingDataSummary: "summary",
		IntendedUses:        "uses",
		Limitations:         "lim",
		FairnessAttestations: map[string]any{
			"demographic_parity": 0.92,
		},
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if c.ModelID != "gemini-2.5-flash" {
		t.Errorf("ModelID=%q", c.ModelID)
	}
}

func TestNewModelCard_RequiredFields(t *testing.T) {
	cases := []evidence.ModelCardParams{
		{TenantID: "t", ModelID: "m", ModelVersion: "v", CardMD: "x"},  // no event_id
		{EventID: "e", ModelID: "m", ModelVersion: "v", CardMD: "x"},   // no tenant_id
		{EventID: "e", TenantID: "t", ModelVersion: "v", CardMD: "x"},  // no model_id
		{EventID: "e", TenantID: "t", ModelID: "m", CardMD: "x"},       // no version
		{EventID: "e", TenantID: "t", ModelID: "m", ModelVersion: "v"}, // no card_md
	}
	for i, c := range cases {
		if _, err := evidence.NewModelCard(c); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

// -----------------------------------------------------------------------------
// D2 data_card_registry
// -----------------------------------------------------------------------------

func TestNewDataCard_Happy(t *testing.T) {
	d, err := evidence.NewDataCard(evidence.DataCardParams{
		EventID: "e", TenantID: "t",
		DatasetID:      "rag-corpus-v1",
		DatasetVersion: "2026-05",
		CardMD:         "# Data Card",
		Schema:         map[string]any{"text": "string"},
		Provenance:     "internal-corpus",
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if d.DatasetID != "rag-corpus-v1" {
		t.Errorf("DatasetID=%q", d.DatasetID)
	}
}

// -----------------------------------------------------------------------------
// D2 decision_explanation
// -----------------------------------------------------------------------------

func TestNewDecisionExplanation_Happy(t *testing.T) {
	e, err := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
		EventID: "e", TenantID: "t",
		DecisionID:      "dec-1",
		Audience:        evidence.AudienceLearner,
		ExplanationMD:   "Why this atom?",
		ConfidenceScore: 0.87,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if e.Audience != evidence.AudienceLearner {
		t.Errorf("Audience=%v", e.Audience)
	}
}

func TestNewDecisionExplanation_RejectsBadAudience(t *testing.T) {
	_, err := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
		EventID: "e", TenantID: "t",
		DecisionID: "d", Audience: "regulator", ExplanationMD: "x",
	})
	if err == nil {
		t.Error("expected error on invalid audience")
	}
}

func TestNewDecisionExplanation_RejectsConfidenceOutOfRange(t *testing.T) {
	for _, c := range []float64{-0.1, 1.1, 2.0} {
		_, err := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
			EventID: "e", TenantID: "t", DecisionID: "d",
			Audience: evidence.AudienceLearner, ExplanationMD: "x",
			ConfidenceScore: c,
		})
		if err == nil {
			t.Errorf("expected error for confidence=%v", c)
		}
	}
}

// -----------------------------------------------------------------------------
// D3 red_team_runs
// -----------------------------------------------------------------------------

func TestNewRedTeamRun_Happy(t *testing.T) {
	r, err := evidence.NewRedTeamRun(evidence.RedTeamRunParams{
		EventID: "e", TenantID: "t",
		RunID: "rt-1", AgentID: "a", Verdict: "pass",
		Scenario: map[string]any{"name": "prompt-injection"},
		Findings: map[string]any{"count": 0},
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.LifecycleStage != evidence.LifecyclePreDeploy {
		t.Errorf("LifecycleStage=%v want pre_deploy (default for red-team)", r.LifecycleStage)
	}
}

// -----------------------------------------------------------------------------
// D3 eval_runs
// -----------------------------------------------------------------------------

func TestNewEvalRun_RegressedWhenScoreBelowBaseline(t *testing.T) {
	r, err := evidence.NewEvalRun(evidence.EvalRunParams{
		EventID: "e", TenantID: "t",
		RunID: "ev-1", AgentID: "a", EvalSuite: "deepeval",
		Score:         0.78,
		BaselineScore: 0.85,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !r.Regressed {
		t.Error("Regressed must be true when score < baseline")
	}
}

func TestNewEvalRun_NotRegressedWhenAboveBaseline(t *testing.T) {
	r, err := evidence.NewEvalRun(evidence.EvalRunParams{
		EventID: "e", TenantID: "t",
		RunID: "ev-1", AgentID: "a", EvalSuite: "deepeval",
		Score:         0.92,
		BaselineScore: 0.85,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.Regressed {
		t.Error("Regressed must be false when score > baseline")
	}
}

// -----------------------------------------------------------------------------
// D3 cost_anomalies
// -----------------------------------------------------------------------------

func TestNewCostAnomaly_Happy(t *testing.T) {
	a, err := evidence.NewCostAnomaly(evidence.CostAnomalyParams{
		EventID: "e", TenantID: "t",
		AnomalyID: "an-1", AgentID: "ag",
		BaselineMicros: 1000,
		ObservedMicros: 4500,
		SigmaFactor:    3.5,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if a.SigmaFactor < 3 {
		t.Errorf("SigmaFactor=%v want >=3", a.SigmaFactor)
	}
}

// -----------------------------------------------------------------------------
// D3 circuit_breaker_state — state machine, transitions tracked
// -----------------------------------------------------------------------------

func TestCircuitBreaker_TransitionClosedToOpen(t *testing.T) {
	cb := evidence.NewCircuitBreaker("t", "agent-x")
	if cb.State() != evidence.CircuitClosed {
		t.Errorf("initial state=%v want closed", cb.State())
	}
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != evidence.CircuitOpen {
		t.Errorf("after 5 failures state=%v want open", cb.State())
	}
	if cb.FailureCount() != 5 {
		t.Errorf("FailureCount=%d want 5", cb.FailureCount())
	}
}

func TestCircuitBreaker_TransitionHalfOpenToClosed(t *testing.T) {
	cb := evidence.NewCircuitBreaker("t", "agent-x")
	cb.TransitionTo(evidence.CircuitHalfOpen)
	cb.RecordSuccess()
	if cb.State() != evidence.CircuitClosed {
		t.Errorf("state=%v want closed after success in half_open", cb.State())
	}
}

// -----------------------------------------------------------------------------
// D3 quarantine_state
// -----------------------------------------------------------------------------

func TestQuarantine_QuarantineAndRelease(t *testing.T) {
	q := evidence.NewQuarantine("t", "agent-x", "circuit_breaker_open")
	if q.IsActive() != true {
		t.Error("expected active after creation")
	}
	if q.QuarantinedAt.IsZero() {
		t.Error("QuarantinedAt must be populated")
	}
	q.Release()
	if q.IsActive() {
		t.Error("expected inactive after Release")
	}
	if q.ReleasedAt == nil {
		t.Error("ReleasedAt must be populated after Release")
	}
}

// -----------------------------------------------------------------------------
// D4 bias_test_runs
// -----------------------------------------------------------------------------

func TestNewBiasTestRun_PassedWhenScoreAboveThreshold(t *testing.T) {
	r, err := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
		EventID: "e", TenantID: "t",
		RunID: "bt-1", AgentID: "ag",
		ProtectedAttribute: "gender",
		TestType:           "demographic_parity",
		Score:              0.95,
		Threshold:          0.8,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !r.Passed {
		t.Error("Passed must be true when score>=threshold")
	}
}

func TestNewBiasTestRun_FailedWhenBelowThreshold(t *testing.T) {
	r, err := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
		EventID: "e", TenantID: "t",
		RunID: "bt-1", AgentID: "ag",
		ProtectedAttribute: "race",
		TestType:           "equal_opportunity",
		Score:              0.65,
		Threshold:          0.8,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.Passed {
		t.Error("Passed must be false when score<threshold")
	}
}

// -----------------------------------------------------------------------------
// D4 hitl_decision_log
// -----------------------------------------------------------------------------

func TestNewHITLDecision_Happy(t *testing.T) {
	d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "e", TenantID: "t",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		OperatorGcid:  "op-1",
		Decision:      evidence.HitlApprove,
		AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if d.Decision != evidence.HitlApprove {
		t.Errorf("Decision=%v", d.Decision)
	}
}

func TestNewHITLDecision_RejectsLevel3(t *testing.T) {
	_, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "e", TenantID: "t",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		OperatorGcid:  "op-1",
		Decision:      evidence.HitlApprove,
		AutonomyLevel: evidence.AutonomyLevel("hitl_l3"),
	})
	if err == nil {
		t.Error("MUST reject Level 3 autonomy per ADR-141")
	}
}

func TestNewHITLDecision_RejectsBadDecision(t *testing.T) {
	_, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "e", TenantID: "t",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		OperatorGcid:  "op-1",
		Decision:      "approved",
		AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err == nil {
		t.Error("expected invalid-decision error")
	}
}

// TestNewHITLDecision_AssigneeNilIsUnassigned exercises the
// self-claimed-model default: nil AssigneeGcid in → nil AssigneeGcid out
// (the canonical "unassigned" semantic on the pending queue).
func TestNewHITLDecision_AssigneeNilIsUnassigned(t *testing.T) {
	d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "e", TenantID: "t",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		OperatorGcid:  "op-1",
		Decision:      evidence.HitlApprove,
		AutonomyLevel: evidence.AutonomyHitlL1,
		// AssigneeGcid intentionally omitted → nil.
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if d.AssigneeGcid != nil {
		t.Errorf("AssigneeGcid = %q; want nil (unassigned)", *d.AssigneeGcid)
	}
}

// TestNewHITLDecision_AssigneeSetCarriesThrough exercises the
// reviewer-claimed path: when a non-blank GCID is passed, it round-trips
// onto the aggregate (trimmed).
func TestNewHITLDecision_AssigneeSetCarriesThrough(t *testing.T) {
	alice := "  alice-gcid  " // intentional surrounding whitespace
	d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "e", TenantID: "t",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		OperatorGcid:  "op-1",
		AssigneeGcid:  &alice,
		Decision:      evidence.HitlApprove,
		AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if d.AssigneeGcid == nil {
		t.Fatal("AssigneeGcid = nil; want trimmed claimant GCID")
	}
	if *d.AssigneeGcid != "alice-gcid" {
		t.Errorf("AssigneeGcid = %q; want %q (trimmed)", *d.AssigneeGcid, "alice-gcid")
	}
}

// TestNewHITLDecision_AssigneeBlankRejected — blank-after-trim is NOT a
// valid GCID and must NOT be treated as "unassigned"; callers must pass nil.
// This prevents synthetic placeholders from masquerading as null.
func TestNewHITLDecision_AssigneeBlankRejected(t *testing.T) {
	for _, blank := range []string{"", " ", "\t", "\n"} {
		blank := blank // capture
		_, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
			EventID: "e", TenantID: "t",
			DecisionID:    "dec-1",
			RunID:         "run-1",
			OperatorGcid:  "op-1",
			AssigneeGcid:  &blank,
			Decision:      evidence.HitlApprove,
			AutonomyLevel: evidence.AutonomyHitlL1,
		})
		if err == nil {
			t.Errorf("AssigneeGcid=%q (blank after trim) must be rejected — callers pass nil for unassigned", blank)
		}
	}
}

// -----------------------------------------------------------------------------
// HitlPending sentinel + NewPendingHITLDecision (O+ Human-Oversight PENDING gate)
//
// A PENDING gate is the row a qgen HITL escalation lands as: no operator has
// decided yet (operator_gcid blank), and the verdict sentinel is "pending".
// The constructor MUST build such a row WITHOUT requiring operator_gcid and
// WITHOUT requiring a terminal approve|reject|edit verdict — and the resulting
// aggregate MUST be non-terminal so the existing Claim/Approve/Reject lifecycle
// can later resolve it.
// -----------------------------------------------------------------------------

// TestHitlPending_NotValidVerdict — the pending sentinel is deliberately NOT a
// canonical verdict. terminalVerdict() == Decision.Valid(), so pending must
// report invalid to keep the gate claimable/decidable.
func TestHitlPending_NotValidVerdict(t *testing.T) {
	if evidence.HitlPending.Valid() {
		t.Fatal("HitlPending MUST NOT be a valid (terminal) verdict — it is the pre-verdict sentinel")
	}
	if string(evidence.HitlPending) != "pending" {
		t.Errorf("HitlPending = %q; want \"pending\"", evidence.HitlPending)
	}
}

func TestNewPendingHITLDecision_Happy(t *testing.T) {
	d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       "ev-pending-1",
		TenantID:      "tenant-1",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		AutonomyLevel: evidence.AutonomyHitlL0,
		Summary:       "qgen exhausted retries with a quality warning",
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if d.Decision != evidence.HitlPending {
		t.Errorf("Decision = %q; want pending", d.Decision)
	}
	if d.OperatorGcid != "" {
		t.Errorf("OperatorGcid = %q; want empty (no operator on a pending gate)", d.OperatorGcid)
	}
	if d.AssigneeGcid != nil {
		t.Errorf("AssigneeGcid = %v; want nil (unassigned at creation)", d.AssigneeGcid)
	}
	if d.AutonomyLevel != evidence.AutonomyHitlL0 {
		t.Errorf("AutonomyLevel = %q; want hitl_l0", d.AutonomyLevel)
	}
	// The summary is preserved on the row (surfaced via Note → edit_payload) so
	// the O+ queue can render WHY the gate was raised.
	if d.Note != "qgen exhausted retries with a quality warning" {
		t.Errorf("Note = %q; want the summary", d.Note)
	}
}

// CHO-2368 P2 — the O+ pending card must show WHICH agent raised the gate.
// hitl_decision_log has no agent_id column, so the value rides edit_payload
// under the reserved key (same least-invasive pattern as operator_note).
func TestNewPendingHITLDecision_CarriesAgentID(t *testing.T) {
	d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       "ev-pending-agent",
		TenantID:      "tenant-1",
		DecisionID:    "prompt-override-plan:plan-1",
		RunID:         "eval-run-1",
		AutonomyLevel: evidence.AutonomyHitlL0,
		AgentID:       "prompt-registry",
		Summary:       "prompt override plan plan-1 passed eval",
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if got, _ := d.EditPayload[evidence.AgentIDEditPayloadKey].(string); got != "prompt-registry" {
		t.Errorf("EditPayload[%q] = %q; want prompt-registry", evidence.AgentIDEditPayloadKey, got)
	}
}

func TestNewPendingHITLDecision_BlankAgentIDStaysAbsent(t *testing.T) {
	d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       "ev-pending-noagent",
		TenantID:      "tenant-1",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		AutonomyLevel: evidence.AutonomyHitlL0,
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if _, present := d.EditPayload[evidence.AgentIDEditPayloadKey]; present {
		t.Error("blank AgentID must not plant an edit_payload key")
	}
}

// TestNewPendingHITLDecision_IsResolvableLater asserts the pending aggregate is
// non-terminal: a reviewer can Claim it and an operator can Approve/Reject it.
// This is the load-bearing property — the PENDING row is the START of the gate
// lifecycle, not a frozen ledger entry.
func TestNewPendingHITLDecision_IsResolvableLater(t *testing.T) {
	d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       "ev-pending-1",
		TenantID:      "tenant-1",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		AutonomyLevel: evidence.AutonomyHitlL0,
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("pending gate must be claimable; Claim: %v", err)
	}
	if err := d.Approve("alice-gcid", "looks good", time.Now().UTC()); err != nil {
		t.Fatalf("pending gate must be approvable; Approve: %v", err)
	}
	if d.Decision != evidence.HitlApprove {
		t.Errorf("post-Approve Decision = %q; want approve", d.Decision)
	}
	if d.OperatorGcid != "alice-gcid" {
		t.Errorf("post-Approve OperatorGcid = %q; want alice-gcid", d.OperatorGcid)
	}
}

func TestNewPendingHITLDecision_RejectsLevel3(t *testing.T) {
	_, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       "ev-1",
		TenantID:      "tenant-1",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		AutonomyLevel: evidence.AutonomyLevel("hitl_l3"),
	})
	if err == nil {
		t.Error("NewPendingHITLDecision MUST reject Level 3 autonomy per ADR-141")
	}
}

func TestNewPendingHITLDecision_RequiresCoreFields(t *testing.T) {
	base := evidence.PendingHITLDecisionParams{
		EventID:       "ev-1",
		TenantID:      "tenant-1",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		AutonomyLevel: evidence.AutonomyHitlL0,
	}
	cases := map[string]func(p *evidence.PendingHITLDecisionParams){
		"event_id":    func(p *evidence.PendingHITLDecisionParams) { p.EventID = "" },
		"tenant_id":   func(p *evidence.PendingHITLDecisionParams) { p.TenantID = "" },
		"decision_id": func(p *evidence.PendingHITLDecisionParams) { p.DecisionID = "" },
		"run_id":      func(p *evidence.PendingHITLDecisionParams) { p.RunID = "" },
	}
	for field, mut := range cases {
		field, mut := field, mut
		t.Run(field, func(t *testing.T) {
			p := base
			mut(&p)
			if _, err := evidence.NewPendingHITLDecision(p); err == nil {
				t.Errorf("missing %s must be rejected", field)
			}
		})
	}
}

// TestNewPendingHITLDecision_DefaultsAutonomyAndLifecycle — a blank autonomy
// level defaults to hitl_l0 (the canonical escalation level) and a blank
// lifecycle stage defaults to runtime, matching the qgen emit contract.
func TestNewPendingHITLDecision_DefaultsAutonomy(t *testing.T) {
	d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:    "ev-1",
		TenantID:   "tenant-1",
		DecisionID: "dec-1",
		RunID:      "run-1",
		// AutonomyLevel intentionally blank.
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if d.AutonomyLevel != evidence.AutonomyHitlL0 {
		t.Errorf("blank autonomy defaulted to %q; want hitl_l0", d.AutonomyLevel)
	}
	if d.LifecycleStage != evidence.LifecycleRuntime {
		t.Errorf("blank lifecycle defaulted to %q; want runtime", d.LifecycleStage)
	}
}

// -----------------------------------------------------------------------------
// Repository — LoadHITLDecision / UpdateAssigneeGcid (N7 self-claim wiring)
// -----------------------------------------------------------------------------

func TestInMemoryRepository_LoadHITLDecision_NotFound(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	_, err := repo.LoadHITLDecision(context.Background(), "tenant-1", "missing")
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Errorf("err = %v; want ErrNotFound", err)
	}
}

func TestInMemoryRepository_LoadHITLDecision_TenantScoped(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "ev-1", TenantID: "tenant-1",
		DecisionID: "dec-42", RunID: "run-1", OperatorGcid: "op-1",
		Decision: evidence.HitlApprove, AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("Append: %v", err)
	}
	_, err = repo.LoadHITLDecision(context.Background(), "tenant-other", "dec-42")
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Errorf("cross-tenant load: err = %v; want ErrNotFound", err)
	}
	got, err := repo.LoadHITLDecision(context.Background(), "tenant-1", "dec-42")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.DecisionID != "dec-42" {
		t.Errorf("DecisionID = %q; want dec-42", got.DecisionID)
	}
}

func TestInMemoryRepository_UpdateAssigneeGcid_SetThenClear(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "ev-1", TenantID: "tenant-1",
		DecisionID: "dec-42", RunID: "run-1", OperatorGcid: "op-1",
		Decision: evidence.HitlApprove, AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("Append: %v", err)
	}
	alice := "alice-gcid"
	if err := repo.UpdateAssigneeGcid(context.Background(), "tenant-1", "dec-42", &alice, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAssigneeGcid set: %v", err)
	}
	got, _ := repo.LoadHITLDecision(context.Background(), "tenant-1", "dec-42")
	if got.AssigneeGcid == nil || *got.AssigneeGcid != "alice-gcid" {
		t.Errorf("AssigneeGcid post-set = %v; want alice-gcid", got.AssigneeGcid)
	}
	if err := repo.UpdateAssigneeGcid(context.Background(), "tenant-1", "dec-42", nil, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAssigneeGcid clear: %v", err)
	}
	got, _ = repo.LoadHITLDecision(context.Background(), "tenant-1", "dec-42")
	if got.AssigneeGcid != nil {
		t.Errorf("AssigneeGcid post-clear = %v; want nil", got.AssigneeGcid)
	}
}

func TestInMemoryRepository_UpdateAssigneeGcid_NotFound(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	alice := "alice-gcid"
	err := repo.UpdateAssigneeGcid(context.Background(), "tenant-1", "missing", &alice, time.Now().UTC())
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Errorf("err = %v; want ErrNotFound", err)
	}
}

// TestInMemoryRepository_AppendPendingHITL_QueryReturnsIt verifies the
// full PENDING-gate round-trip: a pending row appends, then surfaces via
// QueryHITLDecisions with Decision="pending" (the /api/hitl/pending source).
func TestInMemoryRepository_AppendPendingHITL_QueryReturnsIt(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       "ev-pending-1",
		TenantID:      "tenant-1",
		DecisionID:    "dec-42",
		RunID:         "run-1",
		AutonomyLevel: evidence.AutonomyHitlL0,
		Summary:       "quality warning at max retries",
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("AppendHITLDecision: %v", err)
	}
	got, err := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{TenantID: "tenant-1"})
	if err != nil {
		t.Fatalf("QueryHITLDecisions: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("QueryHITLDecisions returned %d rows; want 1 pending", len(got))
	}
	if got[0].Decision != evidence.HitlPending {
		t.Errorf("Decision = %q; want pending", got[0].Decision)
	}
	if got[0].OperatorGcid != "" {
		t.Errorf("OperatorGcid = %q; want empty on a pending gate", got[0].OperatorGcid)
	}
	if got[0].Note != "quality warning at max retries" {
		t.Errorf("Note = %q; want the summary (rehydrated from edit_payload)", got[0].Note)
	}
}

// -----------------------------------------------------------------------------
// HITLDecision.Claim / Release (N7 self-claim endpoint domain logic)
// -----------------------------------------------------------------------------

func newPendingHITLDecision(t *testing.T) *evidence.HITLDecision {
	t.Helper()
	d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       "ev-1",
		TenantID:      "tenant-1",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	return d
}

func TestHITLDecision_Claim_Happy(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if d.AssigneeGcid == nil || *d.AssigneeGcid != "alice-gcid" {
		t.Errorf("AssigneeGcid = %v; want alice-gcid", d.AssigneeGcid)
	}
}

func TestHITLDecision_Claim_TrimsAndCanonicalises(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Claim("  bob-gcid  ", time.Now().UTC()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if d.AssigneeGcid == nil || *d.AssigneeGcid != "bob-gcid" {
		t.Errorf("AssigneeGcid = %v; want trimmed bob-gcid", d.AssigneeGcid)
	}
}

func TestHITLDecision_Claim_BlankGcidRejected(t *testing.T) {
	for _, blank := range []string{"", " ", "\t"} {
		d := newPendingHITLDecision(t)
		err := d.Claim(blank, time.Now().UTC())
		if err == nil {
			t.Errorf("Claim(%q) must reject blank GCID", blank)
		}
	}
}

func TestHITLDecision_Claim_AlreadyClaimedRejected(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("first Claim: %v", err)
	}
	err := d.Claim("bob-gcid", time.Now().UTC())
	if err == nil {
		t.Error("second Claim by different reviewer must be rejected (409 conflict)")
	}
	if !errors.Is(err, evidence.ErrHITLAlreadyClaimed) {
		t.Errorf("err = %v; want ErrHITLAlreadyClaimed", err)
	}
}

func TestHITLDecision_Claim_SameAssigneeIdempotent(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("first Claim: %v", err)
	}
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Errorf("re-claim by same assignee must be idempotent; got %v", err)
	}
}

func TestHITLDecision_Claim_TerminalDecisionRejected(t *testing.T) {
	for _, verdict := range []evidence.HitlVerdict{evidence.HitlApprove, evidence.HitlReject, evidence.HitlEdit} {
		d := newPendingHITLDecision(t)
		d.Decision = verdict
		err := d.Claim("alice-gcid", time.Now().UTC())
		if err == nil {
			t.Errorf("Claim against verdict=%q must be rejected", verdict)
		}
		if !errors.Is(err, evidence.ErrHITLTerminal) {
			t.Errorf("verdict=%q: err = %v; want ErrHITLTerminal", verdict, err)
		}
	}
}

func TestHITLDecision_Release_Happy(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := d.Release("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if d.AssigneeGcid != nil {
		t.Errorf("AssigneeGcid = %v; want nil after Release", d.AssigneeGcid)
	}
}

func TestHITLDecision_Release_NotAssigneeRejected(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	err := d.Release("bob-gcid", time.Now().UTC())
	if err == nil {
		t.Error("Release by non-assignee must be rejected (403)")
	}
	if !errors.Is(err, evidence.ErrHITLNotAssignee) {
		t.Errorf("err = %v; want ErrHITLNotAssignee", err)
	}
}

func TestHITLDecision_Release_UnassignedRejected(t *testing.T) {
	d := newPendingHITLDecision(t)
	err := d.Release("alice-gcid", time.Now().UTC())
	if err == nil {
		t.Error("Release of an unassigned row must be rejected (no claimant to release)")
	}
}

func TestHITLDecision_Release_BlankGcidRejected(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := d.Release("  ", time.Now().UTC()); err == nil {
		t.Error("Release with blank GCID must be rejected")
	}
}

func TestHITLDecision_Release_TerminalRejected(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Claim("alice-gcid", time.Now().UTC()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	d.Decision = evidence.HitlApprove
	err := d.Release("alice-gcid", time.Now().UTC())
	if err == nil {
		t.Error("Release after verdict was recorded must be rejected")
	}
	if !errors.Is(err, evidence.ErrHITLTerminal) {
		t.Errorf("err = %v; want ErrHITLTerminal", err)
	}
}

// -----------------------------------------------------------------------------
// HITLDecision.Approve / Reject (verdict)
// -----------------------------------------------------------------------------

func TestHITLDecision_Approve_Happy(t *testing.T) {
	d := newPendingHITLDecision(t)
	now := time.Now().UTC()
	if err := d.Approve("alice-gcid", "looks correct", now); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if d.Decision != evidence.HitlApprove {
		t.Errorf("Decision = %q; want approve", d.Decision)
	}
	if d.OperatorGcid != "alice-gcid" {
		t.Errorf("OperatorGcid = %q; want alice-gcid", d.OperatorGcid)
	}
	if !d.DecidedAt.Equal(now) {
		t.Errorf("DecidedAt = %v; want %v", d.DecidedAt, now)
	}
	if d.Note != "looks correct" {
		t.Errorf("Note = %q; want 'looks correct'", d.Note)
	}
	if got, _ := d.EditPayload[evidence.NoteEditPayloadKey].(string); got != "looks correct" {
		t.Errorf("EditPayload[%s] = %q; want note mirrored", evidence.NoteEditPayloadKey, got)
	}
}

func TestHITLDecision_Reject_Happy(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Reject("bob-gcid", "policy fail", time.Now().UTC()); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if d.Decision != evidence.HitlReject {
		t.Errorf("Decision = %q; want reject", d.Decision)
	}
	if d.OperatorGcid != "bob-gcid" {
		t.Errorf("OperatorGcid = %q; want bob-gcid", d.OperatorGcid)
	}
}

func TestHITLDecision_Verdict_TrimsOperatorAndNote(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Approve("  carol-gcid  ", "  spaced note  ", time.Now().UTC()); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if d.OperatorGcid != "carol-gcid" {
		t.Errorf("OperatorGcid = %q; want trimmed", d.OperatorGcid)
	}
	if d.Note != "spaced note" {
		t.Errorf("Note = %q; want trimmed", d.Note)
	}
}

func TestHITLDecision_Verdict_BlankNoteOmitsEditPayloadKey(t *testing.T) {
	d := newPendingHITLDecision(t)
	if err := d.Approve("alice-gcid", "   ", time.Now().UTC()); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if d.Note != "" {
		t.Errorf("Note = %q; want empty", d.Note)
	}
	if _, present := d.EditPayload[evidence.NoteEditPayloadKey]; present {
		t.Error("blank note must NOT write the edit_payload note key")
	}
}

func TestHITLDecision_Verdict_BlankOperatorRejected(t *testing.T) {
	for _, blank := range []string{"", " ", "\t"} {
		d := newPendingHITLDecision(t)
		if err := d.Approve(blank, "n", time.Now().UTC()); err == nil {
			t.Errorf("Approve(%q) must reject blank operator", blank)
		}
		d2 := newPendingHITLDecision(t)
		if err := d2.Reject(blank, "n", time.Now().UTC()); err == nil {
			t.Errorf("Reject(%q) must reject blank operator", blank)
		}
	}
}

func TestHITLDecision_Verdict_TerminalRejected(t *testing.T) {
	for _, verdict := range []evidence.HitlVerdict{evidence.HitlApprove, evidence.HitlReject, evidence.HitlEdit} {
		d := newPendingHITLDecision(t)
		d.Decision = verdict // already decided ⇒ terminal
		if err := d.Approve("alice-gcid", "", time.Now().UTC()); !errors.Is(err, evidence.ErrHITLTerminal) {
			t.Errorf("Approve on terminal(%q): err = %v; want ErrHITLTerminal", verdict, err)
		}
		d2 := newPendingHITLDecision(t)
		d2.Decision = verdict
		if err := d2.Reject("alice-gcid", "", time.Now().UTC()); !errors.Is(err, evidence.ErrHITLTerminal) {
			t.Errorf("Reject on terminal(%q): err = %v; want ErrHITLTerminal", verdict, err)
		}
	}
}

// -----------------------------------------------------------------------------
// InMemoryRepository.RecordHITLVerdict (append-only verdict persistence)
// -----------------------------------------------------------------------------

func TestInMemoryRepository_RecordHITLVerdict_AppendsAndRehydratesNote(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	d := newPendingHITLDecision(t)
	d.TenantID = "tenant-1"
	d.DecisionID = "dec-1"
	if err := d.Approve("alice-gcid", "approved note", time.Now().UTC()); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	d.EventID = "verdict-ev-1" // fresh event_id for the append (handler does this)
	if err := repo.RecordHITLVerdict(context.Background(), d); err != nil {
		t.Fatalf("RecordHITLVerdict: %v", err)
	}
	loaded, err := repo.LoadHITLDecision(context.Background(), "tenant-1", "dec-1")
	if err != nil {
		t.Fatalf("LoadHITLDecision: %v", err)
	}
	if loaded.Decision != evidence.HitlApprove {
		t.Errorf("loaded Decision = %q; want approve", loaded.Decision)
	}
	if loaded.Note != "approved note" {
		t.Errorf("loaded Note = %q; want rehydrated from edit_payload", loaded.Note)
	}
}

func TestInMemoryRepository_RecordHITLVerdict_IdempotentOnEventID(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	d := newPendingHITLDecision(t)
	d.TenantID = "tenant-1"
	d.DecisionID = "dec-1"
	_ = d.Reject("bob-gcid", "", time.Now().UTC())
	d.EventID = "verdict-ev-1"
	if err := repo.RecordHITLVerdict(context.Background(), d); err != nil {
		t.Fatalf("RecordHITLVerdict #1: %v", err)
	}
	// Re-deliver the same event_id — must be a no-op, not an error.
	if err := repo.RecordHITLVerdict(context.Background(), d); err != nil {
		t.Fatalf("RecordHITLVerdict #2 (redelivery): %v", err)
	}
}

// -----------------------------------------------------------------------------
// PolicyViolation
// -----------------------------------------------------------------------------

func TestNewPolicyViolation_Happy(t *testing.T) {
	v, err := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
		EventID: "e", TenantID: "t",
		AgentID:    "ag",
		PolicyName: "no_pii",
		Severity:   "high",
		Detector:   "cloud_dlp",
		Payload:    map[string]any{"matches": 1},
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if v.PolicyName != "no_pii" {
		t.Errorf("PolicyName=%q", v.PolicyName)
	}
}

// -----------------------------------------------------------------------------
// Hashing helper — stable canonical hash for accountability evidence
// -----------------------------------------------------------------------------

func TestEvidenceHash_StableForSameInputs(t *testing.T) {
	p := evidence.AccountabilityParams{
		EventID:      "11111111-1111-1111-1111-111111111111",
		TenantID:     "22222222-2222-2222-2222-222222222222",
		AgentID:      "ag",
		OwnerGcid:    "33333333-3333-3333-3333-333333333333",
		DecisionID:   "d",
		DecisionType: "x",
		Provenance:   map[string]any{"k": "v"},
	}
	a1, _ := evidence.NewAccountabilityEvidence(p)
	a2, _ := evidence.NewAccountabilityEvidence(p)
	if a1.EvidenceHash != a2.EvidenceHash {
		t.Errorf("hash mismatch: %q vs %q", a1.EvidenceHash, a2.EvidenceHash)
	}
}

func TestEvidenceHash_DifferentForDifferentProvenance(t *testing.T) {
	a1, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID: "e", TenantID: "t", AgentID: "ag",
		OwnerGcid: "o", DecisionID: "d", DecisionType: "x",
		Provenance: map[string]any{"k": "v1"},
	})
	a2, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID: "e", TenantID: "t", AgentID: "ag",
		OwnerGcid: "o", DecisionID: "d", DecisionType: "x",
		Provenance: map[string]any{"k": "v2"},
	})
	if a1.EvidenceHash == a2.EvidenceHash {
		t.Error("hash should differ when provenance differs")
	}
}

// -----------------------------------------------------------------------------
// Repository — InMemoryRepository smoke test
// -----------------------------------------------------------------------------

func TestInMemoryRepo_AppendAccountability_IdempotentOnEventID(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	p := evidence.AccountabilityParams{
		EventID: "e1", TenantID: "t", AgentID: "ag",
		OwnerGcid: "o", DecisionID: "d", DecisionType: "x",
	}
	a, _ := evidence.NewAccountabilityEvidence(p)
	if err := repo.AppendAccountability(context.Background(), a); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// Re-append same event_id should be a no-op (not error) per idempotency.
	if err := repo.AppendAccountability(context.Background(), a); err != nil {
		t.Fatalf("re-append must be idempotent, got %v", err)
	}
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("rows=%d want 1 (idempotent)", len(rows))
	}
}

func TestInMemoryRepo_QueryByLifecycleStage(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	a1, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID: "e1", TenantID: "t", AgentID: "ag", OwnerGcid: "o",
		DecisionID: "d", DecisionType: "x", LifecycleStage: evidence.LifecycleRuntime,
	})
	a2, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID: "e2", TenantID: "t", AgentID: "ag", OwnerGcid: "o",
		DecisionID: "d2", DecisionType: "x", LifecycleStage: evidence.LifecyclePreDeploy,
	})
	repo.AppendAccountability(context.Background(), a1)
	repo.AppendAccountability(context.Background(), a2)
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", LifecycleStage: evidence.LifecycleRuntime,
	})
	if len(rows) != 1 {
		t.Errorf("rows=%d want 1 (filtered by lifecycle)", len(rows))
	}
}

func TestInMemoryRepo_QueryByDecisionExplanationAudience(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	for i, aud := range []evidence.Audience{
		evidence.AudienceLearner,
		evidence.AudienceInstructorAdmin,
		evidence.AudienceAuditor,
	} {
		ev, _ := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
			EventID: string(rune('a'+i)) + "-id", TenantID: "t",
			DecisionID: "d", Audience: aud, ExplanationMD: "x",
		})
		repo.AppendDecisionExplanation(context.Background(), ev)
	}
	rows, _ := repo.QueryDecisionExplanation(context.Background(), evidence.QueryFilter{
		TenantID: "t", Audience: evidence.AudienceLearner,
	})
	if len(rows) != 1 {
		t.Errorf("learner rows=%d want 1", len(rows))
	}
}

// -----------------------------------------------------------------------------
// Time consistency — RecordedAt always in UTC
// -----------------------------------------------------------------------------

func TestRecordedAt_UTC(t *testing.T) {
	a, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID: "e", TenantID: "t", AgentID: "ag", OwnerGcid: "o",
		DecisionID: "d", DecisionType: "x",
	})
	if a.RecordedAt.Location() != time.UTC {
		t.Errorf("RecordedAt loc=%v want UTC", a.RecordedAt.Location())
	}
}
