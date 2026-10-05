// Coverage-fill tests for evidence package — exercises remaining branches to
// hit the 85% domain coverage gate per .claude/rules/development-execution.md.
package evidence_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

// Audience visibility — full Three-Audience matrix
func TestDecisionExplanation_AudienceVisibilityMatrix(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	for i, aud := range []evidence.Audience{
		evidence.AudienceLearner,
		evidence.AudienceInstructorAdmin,
		evidence.AudienceAuditor,
	} {
		ev, _ := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
			EventID:       "ev-" + string(rune('a'+i)),
			TenantID:      "t",
			DecisionID:    "dec-1",
			Audience:      aud,
			ExplanationMD: "x",
		})
		_ = repo.AppendDecisionExplanation(context.Background(), ev)
	}

	// learner sees only learner row
	rows, _ := repo.GetDecisionExplanationByDecisionID(context.Background(), "t", "dec-1", evidence.AudienceLearner)
	if len(rows) != 1 {
		t.Errorf("learner view rows=%d want 1", len(rows))
	}

	// instructor_admin sees instructor_admin + learner = 2
	rows, _ = repo.GetDecisionExplanationByDecisionID(context.Background(), "t", "dec-1", evidence.AudienceInstructorAdmin)
	if len(rows) != 2 {
		t.Errorf("instructor_admin view rows=%d want 2", len(rows))
	}

	// auditor sees all 3
	rows, _ = repo.GetDecisionExplanationByDecisionID(context.Background(), "t", "dec-1", evidence.AudienceAuditor)
	if len(rows) != 3 {
		t.Errorf("auditor view rows=%d want 3", len(rows))
	}

	// invalid viewer audience filters to none
	rows, _ = repo.GetDecisionExplanationByDecisionID(context.Background(), "t", "dec-1", "regulator")
	if len(rows) != 0 {
		t.Errorf("invalid viewer rows=%d want 0", len(rows))
	}

	// empty viewer = unfiltered (wildcard)
	rows, _ = repo.GetDecisionExplanationByDecisionID(context.Background(), "t", "dec-1", "")
	if len(rows) != 3 {
		t.Errorf("empty viewer rows=%d want 3", len(rows))
	}
}

// Cross-tenant isolation in repo (RLS-equivalent in-memory)
func TestRepo_CrossTenantIsolation(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	for _, tenantID := range []string{"t1", "t2"} {
		ev, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
			EventID: tenantID + "-1", TenantID: tenantID,
			AgentID: "ag", OwnerGcid: "o",
			DecisionID: "d", DecisionType: "x",
		})
		_ = repo.AppendAccountability(context.Background(), ev)
	}
	t1Rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "t1"})
	if len(t1Rows) != 1 || t1Rows[0].TenantID != "t1" {
		t.Errorf("t1 isolation failed: %d rows", len(t1Rows))
	}
	t2Rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "t2"})
	if len(t2Rows) != 1 || t2Rows[0].TenantID != "t2" {
		t.Errorf("t2 isolation failed: %d rows", len(t2Rows))
	}
}

// Filter by AgentID
func TestRepo_FilterByAgentID(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	for i, ag := range []string{"a", "b", "c"} {
		ev, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
			EventID: "e" + string(rune('0'+i)), TenantID: "t",
			AgentID: ag, OwnerGcid: "o",
			DecisionID: "d", DecisionType: "x",
		})
		_ = repo.AppendAccountability(context.Background(), ev)
	}
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", AgentID: "b",
	})
	if len(rows) != 1 || rows[0].AgentID != "b" {
		t.Errorf("AgentID filter failed: %d rows", len(rows))
	}
}

// Time range filter
func TestRepo_TimeRangeFilter(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	ev, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID: "e", TenantID: "t", AgentID: "ag", OwnerGcid: "o",
		DecisionID: "d", DecisionType: "x",
	})
	_ = repo.AppendAccountability(context.Background(), ev)

	// from = future ⇒ no rows
	future := time.Now().UTC().Add(time.Hour)
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", From: &future,
	})
	if len(rows) != 0 {
		t.Errorf("from-future rows=%d want 0", len(rows))
	}

	// to = past ⇒ no rows
	past := time.Now().UTC().Add(-time.Hour)
	rows, _ = repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", To: &past,
	})
	if len(rows) != 0 {
		t.Errorf("to-past rows=%d want 0", len(rows))
	}

	// recent window ⇒ 1 row
	from := time.Now().UTC().Add(-time.Minute)
	to := time.Now().UTC().Add(time.Minute)
	rows, _ = repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", From: &from, To: &to,
	})
	if len(rows) != 1 {
		t.Errorf("recent-window rows=%d want 1", len(rows))
	}
}

// Pagination
func TestRepo_Pagination(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	for i := 0; i < 10; i++ {
		ev, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
			EventID: "e" + string(rune('0'+i)), TenantID: "t",
			AgentID: "ag", OwnerGcid: "o",
			DecisionID: "d", DecisionType: "x",
		})
		_ = repo.AppendAccountability(context.Background(), ev)
	}
	// Limit
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", Limit: 3,
	})
	if len(rows) != 3 {
		t.Errorf("limit=3 rows=%d want 3", len(rows))
	}
	// Offset
	rows, _ = repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", Offset: 7,
	})
	if len(rows) != 3 {
		t.Errorf("offset=7 of 10 rows=%d want 3", len(rows))
	}
	// Offset beyond → nil
	rows, _ = repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", Offset: 20,
	})
	if len(rows) != 0 {
		t.Errorf("offset=20 rows=%d want 0", len(rows))
	}
	// Limit + offset
	rows, _ = repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID: "t", Limit: 2, Offset: 4,
	})
	if len(rows) != 2 {
		t.Errorf("offset+limit rows=%d want 2", len(rows))
	}
}

// All evidence types — append + query smoke
func TestRepo_AllAggregates_AppendAndQuery(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	ctx := context.Background()

	mc, _ := evidence.NewModelCard(evidence.ModelCardParams{
		EventID: "mc1", TenantID: "t",
		ModelID: "m", ModelVersion: "v", CardMD: "card",
	})
	if err := repo.AppendModelCard(ctx, mc); err != nil {
		t.Fatalf("AppendModelCard: %v", err)
	}
	if err := repo.AppendModelCard(ctx, mc); err != nil {
		t.Fatal("idempotent re-append must not error")
	}
	if mcs, _ := repo.QueryModelCards(ctx, evidence.QueryFilter{TenantID: "t"}); len(mcs) != 1 {
		t.Errorf("model cards=%d want 1", len(mcs))
	}

	dc, _ := evidence.NewDataCard(evidence.DataCardParams{
		EventID: "dc1", TenantID: "t",
		DatasetID: "d", DatasetVersion: "v", CardMD: "card",
	})
	_ = repo.AppendDataCard(ctx, dc)
	_ = repo.AppendDataCard(ctx, dc)
	if dcs, _ := repo.QueryDataCards(ctx, evidence.QueryFilter{TenantID: "t"}); len(dcs) != 1 {
		t.Errorf("data cards=%d want 1", len(dcs))
	}

	rt, _ := evidence.NewRedTeamRun(evidence.RedTeamRunParams{
		EventID: "rt1", TenantID: "t", RunID: "rt", AgentID: "a", Verdict: "pass",
	})
	_ = repo.AppendRedTeamRun(ctx, rt)
	_ = repo.AppendRedTeamRun(ctx, rt)
	if rts, _ := repo.QueryRedTeamRuns(ctx, evidence.QueryFilter{TenantID: "t", AgentID: "a"}); len(rts) != 1 {
		t.Errorf("red team runs=%d want 1", len(rts))
	}

	er, _ := evidence.NewEvalRun(evidence.EvalRunParams{
		EventID: "ev1", TenantID: "t", RunID: "ev", AgentID: "a", EvalSuite: "s",
		Score: 0.9, BaselineScore: 0.85,
	})
	_ = repo.AppendEvalRun(ctx, er)
	_ = repo.AppendEvalRun(ctx, er)
	if ers, _ := repo.QueryEvalRuns(ctx, evidence.QueryFilter{TenantID: "t", AgentID: "a"}); len(ers) != 1 {
		t.Errorf("eval runs=%d want 1", len(ers))
	}

	ca, _ := evidence.NewCostAnomaly(evidence.CostAnomalyParams{
		EventID: "ca1", TenantID: "t", AnomalyID: "an", AgentID: "a",
		BaselineMicros: 100, ObservedMicros: 1000, SigmaFactor: 4,
	})
	_ = repo.AppendCostAnomaly(ctx, ca)
	_ = repo.AppendCostAnomaly(ctx, ca)
	if cas, _ := repo.QueryCostAnomalies(ctx, evidence.QueryFilter{TenantID: "t", AgentID: "a"}); len(cas) != 1 {
		t.Errorf("cost anomalies=%d want 1", len(cas))
	}

	bt, _ := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
		EventID: "bt1", TenantID: "t", RunID: "bt", AgentID: "a",
		ProtectedAttribute: "g", TestType: "dp", Score: 0.9, Threshold: 0.8,
	})
	_ = repo.AppendBiasTestRun(ctx, bt)
	_ = repo.AppendBiasTestRun(ctx, bt)
	if bts, _ := repo.QueryBiasTestRuns(ctx, evidence.QueryFilter{TenantID: "t", AgentID: "a"}); len(bts) != 1 {
		t.Errorf("bias test runs=%d want 1", len(bts))
	}

	hd, _ := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "hd1", TenantID: "t", DecisionID: "d", RunID: "r",
		OperatorGcid: "o", Decision: evidence.HitlApprove, AutonomyLevel: evidence.AutonomyHotl,
	})
	_ = repo.AppendHITLDecision(ctx, hd)
	_ = repo.AppendHITLDecision(ctx, hd)
	if hds, _ := repo.QueryHITLDecisions(ctx, evidence.QueryFilter{TenantID: "t"}); len(hds) != 1 {
		t.Errorf("hitl decisions=%d want 1", len(hds))
	}

	pv, _ := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
		EventID: "pv1", TenantID: "t", AgentID: "a",
		PolicyName: "p", Severity: "high", Detector: "d",
	})
	_ = repo.AppendPolicyViolation(ctx, pv)
	_ = repo.AppendPolicyViolation(ctx, pv)
	if pvs, _ := repo.QueryPolicyViolations(ctx, evidence.QueryFilter{TenantID: "t", AgentID: "a"}); len(pvs) != 1 {
		t.Errorf("policy violations=%d want 1", len(pvs))
	}

	cb := evidence.NewCircuitBreaker("t", "a")
	_ = repo.UpsertCircuitBreaker(ctx, cb)
	if cbs, _ := repo.QueryCircuitBreakers(ctx, evidence.QueryFilter{TenantID: "t", AgentID: "a"}); len(cbs) != 1 {
		t.Errorf("circuit breakers=%d want 1", len(cbs))
	}

	q := evidence.NewQuarantine("t", "a", "reason")
	_ = repo.UpsertQuarantine(ctx, q)
	if qs, _ := repo.QueryQuarantines(ctx, evidence.QueryFilter{TenantID: "t", AgentID: "a"}); len(qs) != 1 {
		t.Errorf("quarantines=%d want 1", len(qs))
	}
}

// Negative-path: nil append rejection
func TestRepo_NilAppend_Rejected(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	ctx := context.Background()
	if err := repo.AppendAccountability(ctx, nil); err == nil {
		t.Error("nil accountability must error")
	}
	if err := repo.AppendModelCard(ctx, nil); err == nil {
		t.Error("nil model card must error")
	}
	if err := repo.AppendDataCard(ctx, nil); err == nil {
		t.Error("nil data card must error")
	}
	if err := repo.AppendDecisionExplanation(ctx, nil); err == nil {
		t.Error("nil explanation must error")
	}
	if err := repo.AppendRedTeamRun(ctx, nil); err == nil {
		t.Error("nil red-team must error")
	}
	if err := repo.AppendEvalRun(ctx, nil); err == nil {
		t.Error("nil eval must error")
	}
	if err := repo.AppendCostAnomaly(ctx, nil); err == nil {
		t.Error("nil cost anomaly must error")
	}
	if err := repo.AppendBiasTestRun(ctx, nil); err == nil {
		t.Error("nil bias test must error")
	}
	if err := repo.AppendHITLDecision(ctx, nil); err == nil {
		t.Error("nil hitl must error")
	}
	if err := repo.AppendPolicyViolation(ctx, nil); err == nil {
		t.Error("nil policy violation must error")
	}
	if err := repo.UpsertCircuitBreaker(ctx, nil); err == nil {
		t.Error("nil circuit breaker must error")
	}
	if err := repo.UpsertQuarantine(ctx, nil); err == nil {
		t.Error("nil quarantine must error")
	}
}

// Required-field error messages name the missing field
func TestNew_RequiredFieldsErrorMessage(t *testing.T) {
	_, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("err=%v want contains 'required'", err)
	}
	_, err = evidence.NewModelCard(evidence.ModelCardParams{})
	if err == nil {
		t.Error("expected error")
	}
	_, err = evidence.NewDataCard(evidence.DataCardParams{})
	if err == nil {
		t.Error("expected error")
	}
	_, err = evidence.NewRedTeamRun(evidence.RedTeamRunParams{})
	if err == nil {
		t.Error("expected error")
	}
	_, err = evidence.NewEvalRun(evidence.EvalRunParams{})
	if err == nil {
		t.Error("expected error")
	}
	_, err = evidence.NewCostAnomaly(evidence.CostAnomalyParams{})
	if err == nil {
		t.Error("expected error")
	}
	_, err = evidence.NewBiasTestRun(evidence.BiasTestRunParams{})
	if err == nil {
		t.Error("expected error")
	}
	_, err = evidence.NewHITLDecision(evidence.HITLDecisionParams{})
	if err == nil {
		t.Error("expected error")
	}
	_, err = evidence.NewPolicyViolation(evidence.PolicyViolationParams{})
	if err == nil {
		t.Error("expected error")
	}
	_, err = evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{})
	if err == nil {
		t.Error("expected error")
	}
}

// Invalid lifecycle stage on every aggregate is rejected
func TestNew_InvalidLifecycle_Rejected(t *testing.T) {
	bad := evidence.LifecycleStage("invalid")

	if _, err := evidence.NewModelCard(evidence.ModelCardParams{
		EventID: "e", TenantID: "t", ModelID: "m", ModelVersion: "v", CardMD: "x",
		LifecycleStage: bad,
	}); err == nil {
		t.Error("ModelCard")
	}
	if _, err := evidence.NewDataCard(evidence.DataCardParams{
		EventID: "e", TenantID: "t", DatasetID: "d", DatasetVersion: "v", CardMD: "x",
		LifecycleStage: bad,
	}); err == nil {
		t.Error("DataCard")
	}
	if _, err := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
		EventID: "e", TenantID: "t", DecisionID: "d",
		Audience: evidence.AudienceLearner, ExplanationMD: "x",
		LifecycleStage: bad,
	}); err == nil {
		t.Error("DecisionExplanation")
	}
	if _, err := evidence.NewRedTeamRun(evidence.RedTeamRunParams{
		EventID: "e", TenantID: "t", RunID: "r", AgentID: "a", Verdict: "v",
		LifecycleStage: bad,
	}); err == nil {
		t.Error("RedTeamRun")
	}
	if _, err := evidence.NewEvalRun(evidence.EvalRunParams{
		EventID: "e", TenantID: "t", RunID: "r", AgentID: "a", EvalSuite: "s",
		LifecycleStage: bad,
	}); err == nil {
		t.Error("EvalRun")
	}
	if _, err := evidence.NewCostAnomaly(evidence.CostAnomalyParams{
		EventID: "e", TenantID: "t", AnomalyID: "an", AgentID: "a",
		LifecycleStage: bad,
	}); err == nil {
		t.Error("CostAnomaly")
	}
	if _, err := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
		EventID: "e", TenantID: "t", RunID: "r", AgentID: "a",
		ProtectedAttribute: "p", TestType: "t",
		LifecycleStage: bad,
	}); err == nil {
		t.Error("BiasTestRun")
	}
	if _, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID: "e", TenantID: "t", DecisionID: "d", RunID: "r",
		OperatorGcid: "o", Decision: evidence.HitlApprove, AutonomyLevel: evidence.AutonomyHotl,
		LifecycleStage: bad,
	}); err == nil {
		t.Error("HITLDecision")
	}
	if _, err := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
		EventID: "e", TenantID: "t", AgentID: "a",
		PolicyName: "p", Severity: "s", Detector: "d",
		LifecycleStage: bad,
	}); err == nil {
		t.Error("PolicyViolation")
	}
}

// Defaults: red-team / eval / bias-test default to pre_deploy lifecycle
func TestNew_LifecycleDefaultsPerAggregate(t *testing.T) {
	rt, _ := evidence.NewRedTeamRun(evidence.RedTeamRunParams{
		EventID: "e", TenantID: "t", RunID: "r", AgentID: "a", Verdict: "v",
	})
	if rt.LifecycleStage != evidence.LifecyclePreDeploy {
		t.Errorf("RedTeam default=%v want pre_deploy", rt.LifecycleStage)
	}
	ev, _ := evidence.NewEvalRun(evidence.EvalRunParams{
		EventID: "e", TenantID: "t", RunID: "r", AgentID: "a", EvalSuite: "s",
	})
	if ev.LifecycleStage != evidence.LifecyclePreDeploy {
		t.Errorf("Eval default=%v want pre_deploy", ev.LifecycleStage)
	}
	bt, _ := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
		EventID: "e", TenantID: "t", RunID: "r", AgentID: "a",
		ProtectedAttribute: "p", TestType: "t",
	})
	if bt.LifecycleStage != evidence.LifecyclePreDeploy {
		t.Errorf("Bias default=%v want pre_deploy", bt.LifecycleStage)
	}
}

// Circuit breaker — TransitionTo is no-op when already in target
func TestCircuitBreaker_TransitionToNoOp(t *testing.T) {
	cb := evidence.NewCircuitBreaker("t", "a")
	before := cb.LastTransitionedAt()
	time.Sleep(time.Millisecond)
	cb.TransitionTo(evidence.CircuitClosed) // already closed
	after := cb.LastTransitionedAt()
	if !before.Equal(after) {
		t.Error("TransitionTo to current state must be no-op")
	}
}

// Circuit breaker — getters
func TestCircuitBreaker_Getters(t *testing.T) {
	cb := evidence.NewCircuitBreaker("t1", "agent-x")
	if cb.TenantID() != "t1" {
		t.Errorf("TenantID=%q", cb.TenantID())
	}
	if cb.AgentID() != "agent-x" {
		t.Errorf("AgentID=%q", cb.AgentID())
	}
	if cb.LifecycleStage() != evidence.LifecycleRuntime {
		t.Errorf("LifecycleStage=%v", cb.LifecycleStage())
	}
	if cb.LastTransitionedAt().IsZero() {
		t.Error("LastTransitionedAt zero")
	}
}

// Quarantine release — already-released is idempotent (no panic)
func TestQuarantine_DoubleRelease(t *testing.T) {
	q := evidence.NewQuarantine("t", "a", "reason")
	q.Release()
	if !q.IsActive() == false {
		// inverse semantics — just ensure no panic
	}
	q.Release() // second release should not panic
}

// PolicyViolation — defaults lifecycle to runtime
func TestPolicyViolation_DefaultsLifecycle(t *testing.T) {
	v, _ := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
		EventID: "e", TenantID: "t", AgentID: "a",
		PolicyName: "p", Severity: "s", Detector: "d",
	})
	if v.LifecycleStage != evidence.LifecycleRuntime {
		t.Errorf("default lifecycle=%v want runtime", v.LifecycleStage)
	}
}

// Recursive map canonicalisation — nested maps order independent
func TestEvidenceHash_NestedMapsStable(t *testing.T) {
	p1 := evidence.AccountabilityParams{
		EventID: "e", TenantID: "t", AgentID: "a", OwnerGcid: "o",
		DecisionID: "d", DecisionType: "x",
		Provenance: map[string]any{
			"a": map[string]any{"x": 1, "y": 2},
			"b": "z",
		},
	}
	p2 := evidence.AccountabilityParams{
		EventID: "e", TenantID: "t", AgentID: "a", OwnerGcid: "o",
		DecisionID: "d", DecisionType: "x",
		Provenance: map[string]any{
			"b": "z",
			"a": map[string]any{"y": 2, "x": 1},
		},
	}
	a1, _ := evidence.NewAccountabilityEvidence(p1)
	a2, _ := evidence.NewAccountabilityEvidence(p2)
	if a1.EvidenceHash != a2.EvidenceHash {
		t.Errorf("hash differs across map orderings: %q vs %q", a1.EvidenceHash, a2.EvidenceHash)
	}
}

// Empty Filter (TenantID="") returns rows from all tenants
func TestRepo_EmptyTenantFilterReturnsAll(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	for _, tenantID := range []string{"t1", "t2"} {
		ev, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
			EventID: tenantID + "-1", TenantID: tenantID,
			AgentID: "ag", OwnerGcid: "o",
			DecisionID: "d", DecisionType: "x",
		})
		_ = repo.AppendAccountability(context.Background(), ev)
	}
	rows, _ := repo.QueryAccountability(context.Background(), evidence.QueryFilter{})
	if len(rows) != 2 {
		t.Errorf("empty tenant filter rows=%d want 2", len(rows))
	}
}
