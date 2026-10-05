// default_registry_extra_test.go — fills the remaining rubric auto-fn gaps
// (model cards, red-team runs, regression detection, bias-test pass-rate,
// severity/decision-type/audience filters, circuit-breaker half-open) plus
// DerivationMode.Valid and the auto-fn query-error fail-closed paths.
//
// Follows the same style as resolver_test.go: seed evidence via the
// in-memory repository, resolve through the canonical default registry and
// assert the rubric status through the configured auto_query_key.
package rubric_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
)

func TestDerivationMode_Valid(t *testing.T) {
	t.Parallel()
	valid := []rubric.DerivationMode{rubric.ModeAuto, rubric.ModeStatic}
	for _, m := range valid {
		if !m.Valid() {
			t.Errorf("DerivationMode(%q).Valid() = false; want true", m)
		}
	}
	if (rubric.DerivationMode("bogus")).Valid() {
		t.Error("DerivationMode(bogus).Valid() = true; want false")
	}
	if (rubric.DerivationMode("")).Valid() {
		t.Error("DerivationMode(\"\").Valid() = true; want false")
	}
}

// resolveAutoItem resolves a single auto item through a fresh resolver and
// returns its status.
func resolveAutoItem(t *testing.T, repo evidence.Repository, dimension, key string) rubric.Status {
	t.Helper()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			dimension: {
				Items: []rubric.ConfigItem{
					{ID: key, Title: "Item", EvidenceSource: "log",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: key},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), "tenant-1", dimension)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Resolve returned %d items; want 1", len(items))
	}
	return items[0].Status
}

func TestDefaultRegistry_ModelVersionTracking_Bands(t *testing.T) {
	t.Parallel()
	const dim = "transparency"
	const key = "model_version_tracking"

	// 0 model cards → FAIL.
	if s := resolveAutoItem(t, newRepo(t), dim, key); s != rubric.StatusFail {
		t.Errorf("0 cards → %q; want FAIL", s)
	}

	// 1 card → PARTIAL.
	repo := newRepo(t)
	for i := 0; i < 1; i++ {
		c, err := evidence.NewModelCard(evidence.ModelCardParams{
			EventID:             uniqueID(t, "ev-mc", i),
			TenantID:            "tenant-1",
			ModelID:             "model-1",
			ModelVersion:        "1.0.0",
			CardMD:              "# card",
			TrainingDataSummary: "summary",
			IntendedUses:        "education",
			Limitations:         "none",
		})
		if err != nil {
			t.Fatalf("NewModelCard: %v", err)
		}
		if err := repo.AppendModelCard(context.Background(), c); err != nil {
			t.Fatalf("AppendModelCard: %v", err)
		}
	}
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusPartial {
		t.Errorf("1 card → %q; want PARTIAL", s)
	}

	// 4 cards → PASS.
	repo = newRepo(t)
	for i := 0; i < 4; i++ {
		c, err := evidence.NewModelCard(evidence.ModelCardParams{
			EventID:             uniqueID(t, "ev-mc", i),
			TenantID:            "tenant-1",
			ModelID:             "model-1",
			ModelVersion:        "1.0.0",
			CardMD:              "# card",
			TrainingDataSummary: "summary",
			IntendedUses:        "education",
			Limitations:         "none",
		})
		if err != nil {
			t.Fatalf("NewModelCard: %v", err)
		}
		if err := repo.AppendModelCard(context.Background(), c); err != nil {
			t.Fatalf("AppendModelCard: %v", err)
		}
	}
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusPass {
		t.Errorf("4 cards → %q; want PASS", s)
	}
}

func seedRedTeam(t *testing.T, repo *evidence.InMemoryRepository, verdicts []string) {
	t.Helper()
	for i, v := range verdicts {
		r, err := evidence.NewRedTeamRun(evidence.RedTeamRunParams{
			EventID:  uniqueID(t, "ev-rt", i),
			TenantID: "tenant-1",
			RunID:    uniqueID(t, "run", i),
			AgentID:  "agt-1",
			Scenario: map[string]any{"prompt": "x"},
			Verdict:  v,
			Findings: map[string]any{},
		})
		if err != nil {
			t.Fatalf("NewRedTeamRun: %v", err)
		}
		if err := repo.AppendRedTeamRun(context.Background(), r); err != nil {
			t.Fatalf("AppendRedTeamRun: %v", err)
		}
	}
}

func TestDefaultRegistry_AdversarialTesting_PassRateBands(t *testing.T) {
	t.Parallel()
	const dim = "safety_and_robustness"
	const key = "adversarial_testing"

	// empty → FAIL
	if s := resolveAutoItem(t, newRepo(t), dim, key); s != rubric.StatusFail {
		t.Errorf("no runs → %q; want FAIL", s)
	}

	cases := []struct {
		name     string
		verdicts []string
		want     rubric.Status
	}{
		{"all pass", []string{"pass", "pass", "pass", "pass", "pass"}, rubric.StatusPass},
		{"80% pass", []string{"pass", "pass", "pass", "pass", "fail"}, rubric.StatusPass},
		{"40% pass", []string{"pass", "pass", "fail", "fail", "fail"}, rubric.StatusPartial},
		{"20% pass", []string{"pass", "fail", "fail", "fail", "fail"}, rubric.StatusFail},
		{"case-insensitive", []string{"PASS", "PASS", "PASS", "PASS", "PASS"}, rubric.StatusPass},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo(t)
			seedRedTeam(t, repo, tc.verdicts)
			if s := resolveAutoItem(t, repo, dim, key); s != tc.want {
				t.Errorf("verdicts=%v → %q; want %q", tc.verdicts, s, tc.want)
			}
		})
	}
}

func seedEvalRunsRegressed(t *testing.T, repo *evidence.InMemoryRepository, n, regressed int) {
	t.Helper()
	for i := 0; i < n; i++ {
		score := 0.9
		baseline := 0.8
		if i < regressed {
			score, baseline = 0.7, 0.8 // score < baseline → Regressed auto-derived
		}
		r, err := evidence.NewEvalRun(evidence.EvalRunParams{
			EventID:       uniqueID(t, "ev-ev", i),
			TenantID:      "tenant-1",
			RunID:         uniqueID(t, "run", i),
			AgentID:       "agt-1",
			EvalSuite:     "deepeval-quality",
			Score:         score,
			BaselineScore: baseline,
		})
		if err != nil {
			t.Fatalf("NewEvalRun: %v", err)
		}
		if err := repo.AppendEvalRun(context.Background(), r); err != nil {
			t.Fatalf("AppendEvalRun: %v", err)
		}
	}
}

func TestDefaultRegistry_RegressionDetection_Bands(t *testing.T) {
	t.Parallel()
	const dim = "safety_and_robustness"
	const key = "regression_detection"

	// no eval runs → FAIL (no regression-detection coverage)
	if s := resolveAutoItem(t, newRepo(t), dim, key); s != rubric.StatusFail {
		t.Errorf("no runs → %q; want FAIL", s)
	}

	cases := []struct {
		name    string
		n, regr int
		want    rubric.Status
	}{
		{"none regressed", 4, 0, rubric.StatusPass},
		{"1 of 4 regressed (75%)", 4, 1, rubric.StatusPartial},
		{"2 of 4 regressed (50%)", 4, 2, rubric.StatusPartial},
		{"all regressed (0%)", 4, 4, rubric.StatusFail},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo(t)
			seedEvalRunsRegressed(t, repo, tc.n, tc.regr)
			if s := resolveAutoItem(t, repo, dim, key); s != tc.want {
				t.Errorf("%d runs %d regressed → %q; want %q", tc.n, tc.regr, s, tc.want)
			}
		})
	}
}

func seedBiasRuns(t *testing.T, repo *evidence.InMemoryRepository, runs []struct {
	attr   string
	passed bool
}) {
	t.Helper()
	for i, r := range runs {
		score, threshold := 0.9, 0.5
		if !r.passed {
			score, threshold = 0.3, 0.5
		}
		br, err := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
			EventID:            uniqueID(t, "ev-bias", i),
			TenantID:           "tenant-1",
			RunID:              uniqueID(t, "run", i),
			AgentID:            "agt-1",
			ProtectedAttribute: r.attr,
			TestType:           "synthetic",
			Score:              score,
			Threshold:          threshold,
		})
		if err != nil {
			t.Fatalf("NewBiasTestRun: %v", err)
		}
		if err := repo.AppendBiasTestRun(context.Background(), br); err != nil {
			t.Fatalf("AppendBiasTestRun: %v", err)
		}
	}
}

func TestDefaultRegistry_BiasTesting_PassRateBands(t *testing.T) {
	t.Parallel()
	const dim = "fairness_and_human_oversight"
	const key = "bias_testing"

	if s := resolveAutoItem(t, newRepo(t), dim, key); s != rubric.StatusFail {
		t.Errorf("no runs → %q; want FAIL", s)
	}

	cases := []struct {
		name string
		runs []struct {
			attr   string
			passed bool
		}
		want rubric.Status
	}{
		{"80% pass", []struct {
			attr   string
			passed bool
		}{{"demographic", true}, {"demographic", true}, {"demographic", true}, {"demographic", true}, {"language", false}}, rubric.StatusPass},
		{"40% pass", []struct {
			attr   string
			passed bool
		}{{"gender", true}, {"gender", true}, {"gender", false}, {"gender", false}, {"gender", false}}, rubric.StatusPartial},
		{"20% pass", []struct {
			attr   string
			passed bool
		}{{"gender", true}, {"gender", false}, {"gender", false}, {"gender", false}, {"gender", false}}, rubric.StatusFail},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo(t)
			seedBiasRuns(t, repo, tc.runs)
			if s := resolveAutoItem(t, repo, dim, key); s != tc.want {
				t.Errorf("runs → %q; want %q", s, tc.want)
			}
		})
	}
}

func TestDefaultRegistry_CostTracking_DecisionTypeFilter(t *testing.T) {
	t.Parallel()
	const dim = "accountability"
	const key = "cost_tracking"

	// 5 cost_recorded rows → PASS (threshold 5).
	repo := newRepo(t)
	for i := 0; i < 5; i++ {
		ev, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
			EventID:      uniqueID(t, "ev-acc", i),
			TenantID:     "tenant-1",
			AgentID:      "agt-1",
			OwnerGcid:    "gcid-1",
			DecisionID:   uniqueID(t, "dec", i),
			DecisionType: "cost_recorded",
		})
		if err != nil {
			t.Fatalf("NewAccountabilityEvidence: %v", err)
		}
		if err := repo.AppendAccountability(context.Background(), ev); err != nil {
			t.Fatalf("AppendAccountability: %v", err)
		}
	}
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusPass {
		t.Errorf("5 cost rows → %q; want PASS", s)
	}

	// rows of the WRONG decision type do not count → FAIL.
	repo = newRepo(t)
	for i := 0; i < 5; i++ {
		ev, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
			EventID:      uniqueID(t, "ev-acc", i),
			TenantID:     "tenant-1",
			AgentID:      "agt-1",
			OwnerGcid:    "gcid-1",
			DecisionID:   uniqueID(t, "dec", i),
			DecisionType: "route",
		})
		if err != nil {
			t.Fatalf("NewAccountabilityEvidence: %v", err)
		}
		if err := repo.AppendAccountability(context.Background(), ev); err != nil {
			t.Fatalf("AppendAccountability: %v", err)
		}
	}
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusFail {
		t.Errorf("5 non-cost rows → %q; want FAIL", s)
	}
}

func TestDefaultRegistry_IOGuardrails_SeverityFilter(t *testing.T) {
	t.Parallel()
	const dim = "safety_and_robustness"
	const key = "io_guardrails"

	seedViolations := func(sev string, n int) *evidence.InMemoryRepository {
		repo := newRepo(t)
		for i := 0; i < n; i++ {
			v, err := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
				EventID:    uniqueID(t, "ev-pv", i),
				TenantID:   "tenant-1",
				AgentID:    "agt-1",
				PolicyName: "io-guardrail",
				Severity:   sev,
				Detector:   "det-1",
			})
			if err != nil {
				t.Fatalf("NewPolicyViolation: %v", err)
			}
			if err := repo.AppendPolicyViolation(context.Background(), v); err != nil {
				t.Fatalf("AppendPolicyViolation: %v", err)
			}
		}
		return repo
	}

	// zero low-severity violations → PASS (inverted).
	repo := seedViolations("high", 3)
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusPass {
		t.Errorf("3 high rows, 0 low → %q; want PASS", s)
	}

	// 2 low → PARTIAL.
	repo = seedViolations("low", 2)
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusPartial {
		t.Errorf("2 low rows → %q; want PARTIAL", s)
	}

	// 6 low → FAIL (rule churn).
	repo = seedViolations("Low", 6) // case-insensitive match
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusFail {
		t.Errorf("6 low rows → %q; want FAIL", s)
	}
}

func TestDefaultRegistry_PolicyViolations_NonZeroBands(t *testing.T) {
	t.Parallel()
	const dim = "safety_and_robustness"
	const key = "content_safety_pipeline"

	seedViolations := func(n int) *evidence.InMemoryRepository {
		repo := newRepo(t)
		for i := 0; i < n; i++ {
			v, err := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
				EventID:    uniqueID(t, "ev-pv", i),
				TenantID:   "tenant-1",
				AgentID:    "agt-1",
				PolicyName: "content-safety",
				Severity:   "medium",
				Detector:   "det-1",
			})
			if err != nil {
				t.Fatalf("NewPolicyViolation: %v", err)
			}
			if err := repo.AppendPolicyViolation(context.Background(), v); err != nil {
				t.Fatalf("AppendPolicyViolation: %v", err)
			}
		}
		return repo
	}

	if s := resolveAutoItem(t, seedViolations(3), dim, key); s != rubric.StatusPartial {
		t.Errorf("3 violations → %q; want PARTIAL", s)
	}
	if s := resolveAutoItem(t, seedViolations(6), dim, key); s != rubric.StatusFail {
		t.Errorf("6 violations → %q; want FAIL", s)
	}
}

func TestDefaultRegistry_SourceAttribution_AudienceFilter(t *testing.T) {
	t.Parallel()
	const dim = "transparency"
	const key = "source_attribution"

	seedExpl := func(n int) *evidence.InMemoryRepository {
		repo := newRepo(t)
		for i := 0; i < n; i++ {
			e, err := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
				EventID:         uniqueID(t, "ev-de", i),
				TenantID:        "tenant-1",
				DecisionID:      uniqueID(t, "dec", i),
				Audience:        evidence.AudienceLearner,
				ExplanationMD:   "# why",
				ConfidenceScore: 0.9,
			})
			if err != nil {
				t.Fatalf("NewDecisionExplanation: %v", err)
			}
			if err := repo.AppendDecisionExplanation(context.Background(), e); err != nil {
				t.Fatalf("AppendDecisionExplanation: %v", err)
			}
		}
		return repo
	}

	// 5 learner explanations → PASS (threshold 5).
	if s := resolveAutoItem(t, seedExpl(5), dim, key); s != rubric.StatusPass {
		t.Errorf("5 learner rows → %q; want PASS", s)
	}
	// 1 → PARTIAL.
	if s := resolveAutoItem(t, seedExpl(1), dim, key); s != rubric.StatusPartial {
		t.Errorf("1 learner row → %q; want PARTIAL", s)
	}
}

func TestDefaultRegistry_CircuitBreaker_HalfOpenIsPartial(t *testing.T) {
	t.Parallel()
	const dim = "safety_and_robustness"
	const key = "circuit_breaker"

	repo := newRepo(t)
	cb := evidence.NewCircuitBreaker("tenant-1", "agt-1")
	cb.TransitionTo(evidence.CircuitHalfOpen)
	if err := repo.UpsertCircuitBreaker(context.Background(), cb); err != nil {
		t.Fatalf("UpsertCircuitBreaker: %v", err)
	}
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusPartial {
		t.Errorf("half-open breaker → %q; want PARTIAL", s)
	}

	// closed breaker in the repo → PASS (nothing open/half-open).
	repo = newRepo(t)
	closed := evidence.NewCircuitBreaker("tenant-1", "agt-1")
	if err := repo.UpsertCircuitBreaker(context.Background(), closed); err != nil {
		t.Fatalf("UpsertCircuitBreaker: %v", err)
	}
	if s := resolveAutoItem(t, repo, dim, key); s != rubric.StatusPass {
		t.Errorf("closed breaker → %q; want PASS", s)
	}
}

// -----------------------------------------------------------------------------
// auto-fn query errors — fail closed
// -----------------------------------------------------------------------------

// failingEvidenceRepo embeds the in-memory repository and fails one named
// query method, letting tests prove every auto-fn's query-error path returns
// StatusFail.
type failingEvidenceRepo struct {
	*evidence.InMemoryRepository
	fail map[string]bool
}

func (f *failingEvidenceRepo) QueryAccountability(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.AccountabilityEvidence, error) {
	if f.fail["accountability"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryAccountability(ctx, filter)
}

func (f *failingEvidenceRepo) QueryPolicyViolations(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.PolicyViolation, error) {
	if f.fail["violations"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryPolicyViolations(ctx, filter)
}

func (f *failingEvidenceRepo) QueryDecisionExplanation(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.DecisionExplanation, error) {
	if f.fail["explanation"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryDecisionExplanation(ctx, filter)
}

func (f *failingEvidenceRepo) QueryModelCards(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.ModelCard, error) {
	if f.fail["modelcards"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryModelCards(ctx, filter)
}

func (f *failingEvidenceRepo) QueryRedTeamRuns(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.RedTeamRun, error) {
	if f.fail["redteam"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryRedTeamRuns(ctx, filter)
}

func (f *failingEvidenceRepo) QueryEvalRuns(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.EvalRun, error) {
	if f.fail["evalruns"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryEvalRuns(ctx, filter)
}

func (f *failingEvidenceRepo) QueryCircuitBreakers(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.CircuitBreaker, error) {
	if f.fail["breakers"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryCircuitBreakers(ctx, filter)
}

func (f *failingEvidenceRepo) QueryBiasTestRuns(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.BiasTestRun, error) {
	if f.fail["bias"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryBiasTestRuns(ctx, filter)
}

func (f *failingEvidenceRepo) QueryHITLDecisions(ctx context.Context, filter evidence.QueryFilter) ([]*evidence.HITLDecision, error) {
	if f.fail["hitl"] {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.QueryHITLDecisions(ctx, filter)
}

func TestDefaultRegistry_AutoFnQueryErrorFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		dimension string
		key       string
		failKey   string
	}{
		{"audit trail", "accountability", "audit_trail_coverage", "accountability"},
		{"cost tracking", "accountability", "cost_tracking", "accountability"},
		{"data quality", "accountability", "data_quality_validation", "violations"},
		{"source attribution", "transparency", "source_attribution", "explanation"},
		{"model cards", "transparency", "model_version_tracking", "modelcards"},
		{"red team", "safety_and_robustness", "adversarial_testing", "redteam"},
		{"eval runs", "safety_and_robustness", "quality_evaluation", "evalruns"},
		{"regression detection", "safety_and_robustness", "regression_detection", "evalruns"},
		{"circuit breaker", "safety_and_robustness", "circuit_breaker", "breakers"},
		{"bias testing", "fairness_and_human_oversight", "bias_testing", "bias"},
		{"demographic bias", "fairness_and_human_oversight", "demographic_bias_testing", "bias"},
		{"hitl gates", "fairness_and_human_oversight", "hitl_approval_gates", "hitl"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			repo := &failingEvidenceRepo{
				InMemoryRepository: evidence.NewInMemoryRepository(),
				fail:               map[string]bool{tc.failKey: true},
			}
			if s := resolveAutoItem(t, repo, tc.dimension, tc.key); s != rubric.StatusFail {
				t.Errorf("query error on %s → %q; want FAIL (fail-closed)", tc.key, s)
			}
		})
	}
}
