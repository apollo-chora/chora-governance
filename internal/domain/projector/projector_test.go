// Package projector — RED tests for the IMDA evidence projector.
//
// The projector subscribes to dimension-tagged Pub/Sub events from S2-S6
// services (envelope.ChoraImdaDimension) and routes payloads into the
// appropriate D1-D4 evidence aggregate. Idempotent on event_id; append-only.
package projector_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

func newProjector() (*projector.Projector, *evidence.InMemoryRepository) {
	repo := evidence.NewInMemoryRepository()
	return projector.New(repo), repo
}

func TestProjector_RoutesD1EventToAccountability(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:        "e1",
		TenantID:       "t",
		ImdaDimension:  "accountability",
		LifecycleStage: "runtime",
		EventType:      "chora.closure.account_closed.v1",
		AgentID:        "agent-closure-orchestrator",
		OwnerGcid:      "o",
		DecisionID:     "dec-closure-1",
		DecisionType:   "close_account",
		Provenance:     map[string]any{"reason": "user_request"},
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D1 rows=%d want 1", len(rows))
	}
}

// TestProjector_D1MergesCrewExtensionFieldsIntoProvenance verifies the
// atomic-napping-spring Phase A2 wiring: the projector merges the
// IncomingEvent's crew + cost extension fields into the evidence row's
// Provenance map so /o/agents can query by crew_name + /o/governance
// Decision Traces can drill via crew_id.
func TestProjector_D1MergesCrewExtensionFieldsIntoProvenance(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:        "e2",
		TenantID:       "t",
		ImdaDimension:  "accountability",
		LifecycleStage: "runtime",
		EventType:      "agent.decision.logged",
		AgentID:        "qgen_crew",
		OwnerGcid:      "g",
		DecisionID:     "assist-abc",
		DecisionType:   "qgen.quality_gate.accepted",
		Provenance:     map[string]any{"decision": "accepted"},

		// Extension fields — flow into the evidence row's Provenance.
		CrewName:         "mcq_ai_assist",
		CrewID:           "assist-abc",
		IsResume:         false,
		IsEvalRun:        true,
		AdapterVersion:   "lora-tenant-acme-v3",
		GuardrailOutcome: "pass",
		PromptTokens:     180,
		CompletionTokens: 100,
		CachedTokens:     15,
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Fatalf("D1 rows=%d want 1", len(rows))
	}
	prov := rows[0].Provenance
	// Original Provenance entry preserved.
	if prov["decision"] != "accepted" {
		t.Errorf("provenance.decision = %v; want accepted", prov["decision"])
	}
	// Extension fields stamped into Provenance.
	if prov["crew_name"] != "mcq_ai_assist" {
		t.Errorf("provenance.crew_name = %v; want mcq_ai_assist", prov["crew_name"])
	}
	if prov["crew_id"] != "assist-abc" {
		t.Errorf("provenance.crew_id = %v; want assist-abc", prov["crew_id"])
	}
	if prov["is_eval_run"] != true {
		t.Errorf("provenance.is_eval_run = %v; want true", prov["is_eval_run"])
	}
	if prov["adapter_version"] != "lora-tenant-acme-v3" {
		t.Errorf("provenance.adapter_version = %v", prov["adapter_version"])
	}
	if prov["guardrail_outcome"] != "pass" {
		t.Errorf("provenance.guardrail_outcome = %v", prov["guardrail_outcome"])
	}
	if prov["prompt_tokens"] != int64(180) {
		t.Errorf("provenance.prompt_tokens = %v; want 180", prov["prompt_tokens"])
	}
	if prov["completion_tokens"] != int64(100) {
		t.Errorf("provenance.completion_tokens = %v; want 100", prov["completion_tokens"])
	}
	if prov["cached_tokens"] != int64(15) {
		t.Errorf("provenance.cached_tokens = %v; want 15", prov["cached_tokens"])
	}
	// Zero-value extension fields (is_resume=false) are omitted from
	// Provenance per mergeAccountabilityProvenance — keeps the map small
	// on the production happy-path.
	if _, ok := prov["is_resume"]; ok {
		t.Errorf("provenance.is_resume should be omitted when false; got %v", prov["is_resume"])
	}
}

func TestProjector_RoutesD2ModelCardEvent(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "transparency",
		EventType:     "chora.ai_kernel.model_card_registered.v1",
		ModelID:       "gemini-2.5",
		ModelVersion:  "v1",
		CardMD:        "# Card",
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryModelCards(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D2 model card rows=%d want 1", len(rows))
	}
}

func TestProjector_RoutesD2DataCardEvent(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:        "e1",
		TenantID:       "t",
		ImdaDimension:  "transparency",
		EventType:      "chora.ai_kernel.data_card_registered.v1",
		DatasetID:      "rag-1",
		DatasetVersion: "v1",
		CardMD:         "# Data",
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryDataCards(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D2 data card rows=%d want 1", len(rows))
	}
}

func TestProjector_RoutesD2DecisionExplanation(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:         "e1",
		TenantID:        "t",
		ImdaDimension:   "transparency",
		EventType:       "chora.ai_kernel.decision_explained.v1",
		DecisionID:      "dec-1",
		Audience:        "learner",
		ExplanationMD:   "Why this atom?",
		ConfidenceScore: 0.9,
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryDecisionExplanation(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D2 explanation rows=%d want 1", len(rows))
	}
}

func TestProjector_RoutesD3RedTeamRun(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "safety_and_robustness",
		EventType:     "chora.ai_kernel.red_team_run_completed.v1",
		RunID:         "rt1",
		AgentID:       "ag",
		Verdict:       "pass",
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryRedTeamRuns(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D3 red team rows=%d want 1", len(rows))
	}
}

func TestProjector_RoutesD3EvalRun(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "safety_and_robustness",
		EventType:     "chora.ai_kernel.eval_run_completed.v1",
		RunID:         "ev1",
		AgentID:       "ag",
		EvalSuite:     "deepeval",
		Score:         0.85,
		BaselineScore: 0.80,
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryEvalRuns(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D3 eval rows=%d want 1", len(rows))
	}
}

func TestProjector_RoutesD3CostAnomaly(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:        "e1",
		TenantID:       "t",
		ImdaDimension:  "safety_and_robustness",
		EventType:      "chora.observability.cost_anomaly_detected.v1",
		AnomalyID:      "an1",
		AgentID:        "ag",
		BaselineMicros: 1000,
		ObservedMicros: 5000,
		SigmaFactor:    4.2,
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryCostAnomalies(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D3 cost rows=%d want 1", len(rows))
	}
}

func TestProjector_RoutesD3PolicyViolation(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "safety_and_robustness",
		EventType:     "chora.governance.content_policy_violation.v1",
		AgentID:       "ag",
		PolicyName:    "no_pii",
		Severity:      "high",
		Detector:      "cloud_dlp",
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryPolicyViolations(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("policy violation rows=%d want 1", len(rows))
	}
}

func TestProjector_RoutesD4BiasTestRun(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:            "e1",
		TenantID:           "t",
		ImdaDimension:      "fairness_and_human_oversight",
		EventType:          "chora.ai_kernel.bias_test_completed.v1",
		RunID:              "bt1",
		AgentID:            "ag",
		ProtectedAttribute: "gender",
		TestType:           "demographic_parity",
		Score:              0.92,
		Threshold:          0.8,
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryBiasTestRuns(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D4 bias rows=%d want 1", len(rows))
	}
}

func TestProjector_RoutesD4HITLDecision(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "fairness_and_human_oversight",
		EventType:     "chora.governance.hitl_decision_recorded.v1",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		OperatorGcid:  "op",
		HitlVerdict:   "approve",
		AutonomyLevel: "hitl_l1",
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D4 hitl rows=%d want 1", len(rows))
	}
}

// TestProjector_RoutesD4PendingHITLGate is the qgen-escalation contract: a HITL
// gate REQUESTED (hitl_verdict="pending", no operator_gcid) must persist as a
// PENDING hitl_decision_log row — NOT be rejected because the verdict isn't a
// terminal approve|reject|edit. This is the gap the O+ Human-Oversight pipeline
// closes: the qgen orchestrator emits chora.governance.hitl.requested.v1 with
// this exact shape (per commit a977a483).
func TestProjector_RoutesD4PendingHITLGate(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "ev-pending-1",
		TenantID:      "t",
		ImdaDimension: "fairness_and_human_oversight",
		EventType:     "governance.hitl.requested",
		DecisionID:    "dec-1",
		RunID:         "run-1",
		AgentID:       "prompt-registry",
		OperatorGcid:  "", // no operator on a pending gate
		HitlVerdict:   "pending",
		AutonomyLevel: "hitl_l0",
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project (pending HITL gate): %v", err)
	}
	rows, _ := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Fatalf("D4 pending hitl rows=%d want 1", len(rows))
	}
	if rows[0].Decision != evidence.HitlPending {
		t.Errorf("Decision=%q want pending", rows[0].Decision)
	}
	if rows[0].OperatorGcid != "" {
		t.Errorf("OperatorGcid=%q want empty on a pending gate", rows[0].OperatorGcid)
	}
	if rows[0].DecisionID != "dec-1" {
		t.Errorf("DecisionID=%q want dec-1", rows[0].DecisionID)
	}
	// CHO-2368 P2 — the emitting agent rides edit_payload so the O+ card can
	// show which agent raised the gate.
	if got, _ := rows[0].EditPayload[evidence.AgentIDEditPayloadKey].(string); got != "prompt-registry" {
		t.Errorf("EditPayload[agent_id]=%q want prompt-registry", got)
	}
}

// TestProjector_RoutesD4PendingHITLGate_BlankVerdictTreatedPending — a HITL
// event with NO hitl_verdict at all is treated as a pending gate (forward
// compat with emitters that omit the sentinel).
func TestProjector_RoutesD4PendingHITLGate_BlankVerdictTreatedPending(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "ev-pending-2",
		TenantID:      "t",
		ImdaDimension: "fairness_and_human_oversight",
		EventType:     "governance.hitl.requested",
		DecisionID:    "dec-2",
		RunID:         "run-2",
		// HitlVerdict + OperatorGcid intentionally blank.
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project (blank-verdict HITL gate): %v", err)
	}
	rows, _ := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Fatalf("D4 pending hitl rows=%d want 1", len(rows))
	}
	if rows[0].Decision != evidence.HitlPending {
		t.Errorf("Decision=%q want pending", rows[0].Decision)
	}
}

// TestProjector_RoutesD4HITLDecision_ResolvedStillWorks guards that the
// existing RESOLVED-verdict path (approve|reject|edit with an operator) is
// unchanged by the pending-gate addition.
func TestProjector_RoutesD4HITLDecision_ResolvedStillWorks(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "ev-resolved-1",
		TenantID:      "t",
		ImdaDimension: "fairness_and_human_oversight",
		EventType:     "chora.governance.hitl_decision_recorded.v1",
		DecisionID:    "dec-3",
		RunID:         "run-3",
		OperatorGcid:  "op-1",
		HitlVerdict:   "reject",
		AutonomyLevel: "hitl_l1",
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project (resolved HITL): %v", err)
	}
	rows, _ := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Fatalf("D4 resolved hitl rows=%d want 1", len(rows))
	}
	if rows[0].Decision != evidence.HitlReject {
		t.Errorf("Decision=%q want reject", rows[0].Decision)
	}
	if rows[0].OperatorGcid != "op-1" {
		t.Errorf("OperatorGcid=%q want op-1", rows[0].OperatorGcid)
	}
}

func TestProjector_AcceptsDeprecatedV1Aliases(t *testing.T) {
	p, repo := newProjector()
	// Producer sends "risk_levels" (v1 alias); projector must canonicalise to "accountability"
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "risk_levels",
		EventType:     "chora.closure.account_closed.v1",
		AgentID:       "ag",
		OwnerGcid:     "o",
		DecisionID:    "d",
		DecisionType:  "x",
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("v1 alias should canonicalise; D1 rows=%d want 1", len(rows))
	}
}

func TestProjector_IdempotentOnEventID(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "accountability",
		EventType:     "chora.closure.account_closed.v1",
		AgentID:       "ag",
		OwnerGcid:     "o",
		DecisionID:    "d",
		DecisionType:  "x",
	}
	for i := 0; i < 3; i++ {
		if err := p.Project(context.Background(), ev); err != nil {
			t.Fatalf("Project iter %d: %v", i, err)
		}
	}
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("idempotent rows=%d want 1", len(rows))
	}
}

func TestProjector_RejectsMissingDimension(t *testing.T) {
	p, _ := newProjector()
	ev := projector.IncomingEvent{
		EventID:   "e1",
		TenantID:  "t",
		EventType: "chora.something.v1",
	}
	if err := p.Project(context.Background(), ev); err == nil {
		t.Error("expected error on missing imda_dimension")
	}
}

func TestProjector_RejectsUnknownDimension(t *testing.T) {
	p, _ := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "elephant_in_the_room",
		EventType:     "chora.x.y.z.v1",
	}
	if err := p.Project(context.Background(), ev); err == nil {
		t.Error("expected error on unknown imda_dimension")
	}
}

func TestProjector_RejectsRequiredFieldsMissing(t *testing.T) {
	p, _ := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "accountability",
		EventType:     "chora.closure.account_closed.v1",
		// missing agent + decision fields
	}
	if err := p.Project(context.Background(), ev); err == nil {
		t.Error("expected error on missing required D1 fields")
	}
}

func TestProjector_DefaultsMissingLifecycleToRuntime(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "accountability",
		EventType:     "chora.closure.account_closed.v1",
		// LifecycleStage left blank
		AgentID:      "ag",
		OwnerGcid:    "o",
		DecisionID:   "d",
		DecisionType: "x",
	}
	_ = p.Project(context.Background(), ev)
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0].LifecycleStage != evidence.LifecycleRuntime {
		t.Errorf("default lifecycle=%v want runtime", rows[0].LifecycleStage)
	}
}

func TestProjector_LifecycleStageOverride(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:        "e1",
		TenantID:       "t",
		ImdaDimension:  "safety_and_robustness",
		LifecycleStage: "ci_pre_merge",
		EventType:      "chora.ci.security_scan_completed.v1",
		RunID:          "rt1",
		AgentID:        "ag",
		Verdict:        "pass",
	}
	_ = p.Project(context.Background(), ev)
	rows, _ := repo.QueryRedTeamRuns(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0].LifecycleStage != evidence.LifecycleCIPreMerge {
		t.Errorf("lifecycle=%v want ci_pre_merge", rows[0].LifecycleStage)
	}
}

// D2 events without specific event_type fields fall back to decision_explanation
func TestProjector_RoutesD2GenericExplanation(t *testing.T) {
	p, repo := newProjector()
	ev := projector.IncomingEvent{
		EventID:         "e1",
		TenantID:        "t",
		ImdaDimension:   "transparency",
		EventType:       "chora.creation.atom.published.v1",
		DecisionID:      "dec-publish-1",
		Audience:        "auditor",
		ExplanationMD:   "Atom was published after gate verdict pass.",
		ConfidenceScore: 1.0,
	}
	if err := p.Project(context.Background(), ev); err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, _ := repo.QueryDecisionExplanation(context.Background(), evidence.QueryFilter{TenantID: "t"})
	if len(rows) != 1 {
		t.Errorf("D2 generic explanation rows=%d want 1", len(rows))
	}
}
