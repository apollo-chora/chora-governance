// resolver_tail_test.go — covers the last uncovered rubric branches:
//
//   - resolveItem: auto fn returning a per-tenant evidence URL (fallback
//     preference over the configured static EvidenceURL)
//   - resolveItem: default derivation mode (neither static nor auto) → FAIL
//   - PassRate: dimension with zero configured items → (0, nil)
//   - auto-fn query-error paths for the remaining auto keys (io_guardrails,
//     explainability_reasoning, demographic_bias_testing) and the
//     autoFromEvalRuns empty-input FAIL branch
package rubric_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
)

func TestResolve_AutoItemPrefersPerTenantEvidenceURL(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "custom", Title: "Custom", EvidenceSource: "log", DerivationMode: rubric.ModeAuto,
						AutoQueryKey: "custom_key",
						EvidenceURL:  "https://static.example/doc",
					},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, evidence.NewInMemoryRepository())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	r = r.WithFuncRegistry(map[string]rubric.AutoFunc{
		"custom_key": func(_ context.Context, _ string, _ evidence.Repository) (rubric.Status, string, error) {
			return rubric.StatusPass, "https://tenant.example/evidence/1", nil
		},
	})
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].EvidenceSourceURL != "https://tenant.example/evidence/1" {
		t.Errorf("EvidenceSourceURL = %q; want per-tenant URL to win", items[0].EvidenceSourceURL)
	}
	if items[0].Status != rubric.StatusPass {
		t.Errorf("Status = %q; want PASS", items[0].Status)
	}
}

func TestResolve_AutoItemFallsBackToConfiguredURL(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "custom", Title: "Custom", EvidenceSource: "log", DerivationMode: rubric.ModeAuto,
						AutoQueryKey: "custom_key", EvidenceURL: "https://static.example/doc"},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, evidence.NewInMemoryRepository())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	r = r.WithFuncRegistry(map[string]rubric.AutoFunc{
		"custom_key": func(_ context.Context, _ string, _ evidence.Repository) (rubric.Status, string, error) {
			return rubric.StatusPartial, "", nil // no per-tenant URL
		},
	})
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].EvidenceSourceURL != "https://static.example/doc" {
		t.Errorf("EvidenceSourceURL = %q; want configured fallback", items[0].EvidenceSourceURL)
	}
}

func TestResolve_UnknownDerivationModeIsFail(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "bogus", Title: "Bogus", EvidenceSource: "log", DerivationMode: rubric.DerivationMode("yaml-driven")},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, evidence.NewInMemoryRepository())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].Status != rubric.StatusFail {
		t.Errorf("Status = %q; want FAIL (unknown mode)", items[0].Status)
	}
}

func TestPassRate_EmptyItemsReturnsZero(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {Items: []rubric.ConfigItem{}}, // config exists, no items
		},
	}
	r, err := rubric.NewResolver(cfg, evidence.NewInMemoryRepository())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	rate, err := r.PassRate(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("PassRate: %v", err)
	}
	if rate != 0 {
		t.Errorf("PassRate = %v; want 0 for empty dimension", rate)
	}
}

// errViolationsRepo fails QueryPolicyViolations; errExplRepo fails
// QueryDecisionExplanation; errBiasRepo fails QueryBiasTestRuns.
type errViolationsRepo struct {
	*evidence.InMemoryRepository
}

func (f *errViolationsRepo) QueryPolicyViolations(context.Context, evidence.QueryFilter) ([]*evidence.PolicyViolation, error) {
	return nil, errors.New("query boom")
}

type errExplRepo struct {
	*evidence.InMemoryRepository
}

func (f *errExplRepo) QueryDecisionExplanation(context.Context, evidence.QueryFilter) ([]*evidence.DecisionExplanation, error) {
	return nil, errors.New("query boom")
}

type errBiasRepo struct {
	*evidence.InMemoryRepository
}

func (f *errBiasRepo) QueryBiasTestRuns(context.Context, evidence.QueryFilter) ([]*evidence.BiasTestRun, error) {
	return nil, errors.New("query boom")
}

func TestDefaultRegistry_RemainingQueryErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		repo      evidence.Repository
		dimension string
		key       string
	}{
		{"io guardrails", &errViolationsRepo{evidence.NewInMemoryRepository()}, "safety_and_robustness", "io_guardrails"},
		{"explainability", &errExplRepo{evidence.NewInMemoryRepository()}, "transparency", "explainability_reasoning"},
		{"demographic bias", &errBiasRepo{evidence.NewInMemoryRepository()}, "fairness_and_human_oversight", "demographic_bias_testing"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if s := resolveAutoItem(t, tc.repo, tc.dimension, tc.key); s != rubric.StatusFail {
				t.Errorf("query error on %s → %q; want FAIL", tc.key, s)
			}
		})
	}
}

func TestDefaultRegistry_EvalRuns_EmptyIsFail(t *testing.T) {
	t.Parallel()
	// No eval runs → quality_evaluation FAILs (no coverage to report).
	if s := resolveAutoItem(t, newRepo(t), "safety_and_robustness", "quality_evaluation"); s != rubric.StatusFail {
		t.Errorf("empty eval runs → %q; want FAIL", s)
	}
}

func TestDefaultRegistry_DemographicBias_NoMatchingRowsIsFail(t *testing.T) {
	t.Parallel()
	// Bias runs exist but for a different attribute → demographic filter
	// matches zero rows → FAIL.
	repo := newRepo(t)
	for i := 0; i < 3; i++ {
		r, err := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
			EventID:            uniqueID(t, "ev-bias", i),
			TenantID:           "tenant-1",
			RunID:              uniqueID(t, "run", i),
			AgentID:            "agt-1",
			ProtectedAttribute: "language",
			TestType:           "synthetic",
			Score:              0.9,
			Threshold:          0.5,
		})
		if err != nil {
			t.Fatalf("NewBiasTestRun: %v", err)
		}
		if err := repo.AppendBiasTestRun(context.Background(), r); err != nil {
			t.Fatalf("AppendBiasTestRun: %v", err)
		}
	}
	if s := resolveAutoItem(t, repo, "fairness_and_human_oversight", "demographic_bias_testing"); s != rubric.StatusFail {
		t.Errorf("no demographic rows → %q; want FAIL", s)
	}
}
