// resolver_test.go — unit tests for the rubric resolver. Per
// [[tdd-blanket]] 85% domain coverage gate; per [[feedback-no-local-cicd-run]]
// tests run via Cloud Build, not locally.
package rubric_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
)

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func newConfig() rubric.Config {
	return rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "audit", Title: "Audit Trail", EvidenceSource: "Cloud Trace",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "audit_trail_coverage"},
					{ID: "raci", Title: "RACI Matrix", EvidenceSource: "doc",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPartial},
					{ID: "incident", Title: "Incident Runbook", EvidenceSource: "doc",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
				},
			},
			"transparency": {
				Items: []rubric.ConfigItem{
					{ID: "explain", Title: "Explainability", EvidenceSource: "Cloud Trace",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "explainability_reasoning"},
					{ID: "disclosure", Title: "AI Disclosure", EvidenceSource: "doc",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusFail},
				},
			},
		},
	}
}

func newRepo(t *testing.T) *evidence.InMemoryRepository {
	t.Helper()
	return evidence.NewInMemoryRepository()
}

func seedAccountability(t *testing.T, repo *evidence.InMemoryRepository, tenantID string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ev, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
			EventID:      uniqueID(t, "ev-acc", i),
			TenantID:     tenantID,
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
}

func uniqueID(t *testing.T, prefix string, i int) string {
	t.Helper()
	return prefix + "-" + time.Now().UTC().Format("20060102150405") + "-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

// -----------------------------------------------------------------------------
// NewResolver — guard rails
// -----------------------------------------------------------------------------

func TestNewResolver_RejectsEmptyConfig(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	_, err := rubric.NewResolver(rubric.Config{}, repo)
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestNewResolver_RejectsNilRepo(t *testing.T) {
	t.Parallel()
	_, err := rubric.NewResolver(newConfig(), nil)
	if err == nil {
		t.Fatal("expected error for nil repo")
	}
}

func TestNewResolver_AcceptsValidInputs(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
}

// -----------------------------------------------------------------------------
// Resolve — static items pass through
// -----------------------------------------------------------------------------

func TestResolve_StaticItemPassesThrough(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("len(items) = %d; want 3", len(items))
	}
	// raci item — static_status=PARTIAL
	var raci *rubric.RubricItem
	for i := range items {
		if items[i].ID == "raci" {
			raci = &items[i]
		}
	}
	if raci == nil {
		t.Fatal("raci item not found")
	}
	if raci.Status != rubric.StatusPartial {
		t.Errorf("raci.Status = %q; want PARTIAL", raci.Status)
	}
	if raci.DerivationMode != "static" {
		t.Errorf("raci.DerivationMode = %q; want static", raci.DerivationMode)
	}
}

func TestResolve_StaticItemWithInvalidStatusBecomesFail(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "bad", Title: "Bad", EvidenceSource: "x",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.Status("WRONG")},
				},
			},
		},
	}
	repo := newRepo(t)
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].Status != rubric.StatusFail {
		t.Errorf("Status = %q; want FAIL", items[0].Status)
	}
}

// -----------------------------------------------------------------------------
// Resolve — auto items dispatch the function registry
// -----------------------------------------------------------------------------

func TestResolve_AutoItemDispatchesToRegistry(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	// Seed enough rows to hit PASS threshold (>= 10).
	seedAccountability(t, repo, "tenant-1", 12)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var audit *rubric.RubricItem
	for i := range items {
		if items[i].ID == "audit" {
			audit = &items[i]
		}
	}
	if audit == nil {
		t.Fatal("audit item not found")
	}
	if audit.Status != rubric.StatusPass {
		t.Errorf("audit.Status = %q; want PASS", audit.Status)
	}
}

func TestResolve_AutoItemEmptyEvidenceIsFail(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var audit *rubric.RubricItem
	for i := range items {
		if items[i].ID == "audit" {
			audit = &items[i]
		}
	}
	if audit == nil {
		t.Fatal("audit item not found")
	}
	if audit.Status != rubric.StatusFail {
		t.Errorf("audit.Status = %q; want FAIL (no rows)", audit.Status)
	}
}

func TestResolve_AutoItemPartialBand(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	// Seed below PASS threshold (10) but > 0 → PARTIAL.
	seedAccountability(t, repo, "tenant-1", 3)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var audit *rubric.RubricItem
	for i := range items {
		if items[i].ID == "audit" {
			audit = &items[i]
		}
	}
	if audit == nil {
		t.Fatal("audit item not found")
	}
	if audit.Status != rubric.StatusPartial {
		t.Errorf("audit.Status = %q; want PARTIAL", audit.Status)
	}
}

func TestResolve_AutoItemUnknownKeyIsFail(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "ghost", Title: "Ghost", EvidenceSource: "x",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "does_not_exist"},
				},
			},
		},
	}
	repo := newRepo(t)
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].Status != rubric.StatusFail {
		t.Errorf("Status = %q; want FAIL", items[0].Status)
	}
}

func TestResolve_AutoItemFunctionErrorIsFail(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "broken", Title: "Broken", EvidenceSource: "x",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "broken"},
				},
			},
		},
	}
	repo := newRepo(t)
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	// Inject a broken AutoFunc via the test-only override.
	r.WithFuncRegistry(map[string]rubric.AutoFunc{
		"broken": func(_ context.Context, _ string, _ evidence.Repository) (rubric.Status, string, error) {
			return rubric.StatusFail, "", errors.New("simulated db down")
		},
	})
	items, err := r.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].Status != rubric.StatusFail {
		t.Errorf("Status = %q; want FAIL", items[0].Status)
	}
}

// -----------------------------------------------------------------------------
// Resolve — error paths
// -----------------------------------------------------------------------------

func TestResolve_MissingTenantIDRejected(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "", "accountability"); err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
}

func TestResolve_UnknownDimensionRejected(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "tenant-1", "nonsense"); err == nil {
		t.Fatal("expected error for unknown dimension")
	}
}

func TestResolve_DimensionWithNoConfigEntriesRejected(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {Items: []rubric.ConfigItem{
				{ID: "raci", Title: "RACI", EvidenceSource: "doc",
					DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
			}},
		},
	}
	repo := newRepo(t)
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "tenant-1", "transparency"); err == nil {
		t.Fatal("expected error for dimension with no config")
	}
}

func TestResolve_DeprecatedV1AliasIsCanonicalised(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	// risk_levels is the v1 alias for accountability per ADR-141 §3.
	items, err := r.Resolve(context.Background(), "tenant-1", "risk_levels")
	if err != nil {
		t.Fatalf("Resolve(risk_levels): %v", err)
	}
	if len(items) != 3 {
		t.Errorf("len(items) = %d; want 3 (accountability has 3 entries)", len(items))
	}
}

// -----------------------------------------------------------------------------
// ResolveAll
// -----------------------------------------------------------------------------

func TestResolveAll_ReturnsAllConfiguredDimensions(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	all, err := r.ResolveAll(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("ResolveAll: %v", err)
	}
	if _, ok := all["accountability"]; !ok {
		t.Error("missing accountability")
	}
	if _, ok := all["transparency"]; !ok {
		t.Error("missing transparency")
	}
}

func TestResolveAll_RejectsEmptyTenantID(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.ResolveAll(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty tenant_id")
	}
}

// -----------------------------------------------------------------------------
// PassRate
// -----------------------------------------------------------------------------

func TestPassRate_MixedItemsAveragedAt5050(t *testing.T) {
	t.Parallel()
	// accountability has 3 items: audit (auto → FAIL with no data),
	// raci (static PARTIAL), incident (static PASS). Pass rate = (0 + 0.5 + 1) / 3 = 0.5
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	rate, err := r.PassRate(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("PassRate: %v", err)
	}
	if rate < 0.49 || rate > 0.51 {
		t.Errorf("rate = %f; want ~0.5", rate)
	}
}

func TestPassRate_AllPassReturnsOne(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	// Seed enough rows for audit_trail_coverage → PASS (>= 10).
	seedAccountability(t, repo, "tenant-1", 15)
	// transparency has explain (auto → FAIL with no data) + disclosure (static FAIL)
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"all_pass": {
				Items: []rubric.ConfigItem{
					{ID: "a", Title: "A", EvidenceSource: "x",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
					{ID: "b", Title: "B", EvidenceSource: "x",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
				},
			},
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "a", Title: "A", EvidenceSource: "x",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	rate, err := r.PassRate(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("PassRate: %v", err)
	}
	if rate != 1.0 {
		t.Errorf("rate = %f; want 1.0", rate)
	}
}

func TestPassRate_AllFailReturnsZero(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "a", Title: "A", EvidenceSource: "x",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusFail},
					{ID: "b", Title: "B", EvidenceSource: "x",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusFail},
				},
			},
		},
	}
	repo := newRepo(t)
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	rate, err := r.PassRate(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("PassRate: %v", err)
	}
	if rate != 0.0 {
		t.Errorf("rate = %f; want 0.0", rate)
	}
}

func TestPassRate_PropagatesResolveError(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.PassRate(context.Background(), "tenant-1", "nonsense"); err == nil {
		t.Fatal("expected error for unknown dimension")
	}
}

// -----------------------------------------------------------------------------
// Dimensions
// -----------------------------------------------------------------------------

func TestDimensions_ReturnsConfiguredCanonicalOrder(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	r, err := rubric.NewResolver(newConfig(), repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	dims := r.Dimensions()
	if len(dims) != 2 {
		t.Fatalf("len(dims) = %d; want 2", len(dims))
	}
	if dims[0] != "accountability" {
		t.Errorf("dims[0] = %q; want accountability (ADR-141 canonical D1 first)", dims[0])
	}
	if dims[1] != "transparency" {
		t.Errorf("dims[1] = %q; want transparency (ADR-141 canonical D2 second)", dims[1])
	}
}

// -----------------------------------------------------------------------------
// NewDefaultFuncRegistry — verifies expected auto_query_keys exist
// -----------------------------------------------------------------------------

func TestNewDefaultFuncRegistry_ContainsCanonicalKeys(t *testing.T) {
	t.Parallel()
	reg := rubric.NewDefaultFuncRegistry()
	wantKeys := []string{
		"audit_trail_coverage", "cost_tracking", "data_lineage", "data_quality_validation",
		"explainability_reasoning", "source_attribution", "model_version_tracking",
		"content_safety_pipeline", "io_guardrails", "adversarial_testing",
		"quality_evaluation", "regression_detection", "circuit_breaker",
		"bias_testing", "hitl_approval_gates", "demographic_bias_testing",
	}
	for _, k := range wantKeys {
		if _, ok := reg[k]; !ok {
			t.Errorf("registry missing key %q", k)
		}
	}
}

// -----------------------------------------------------------------------------
// Auto-fn integration — exercise the canonical functions via seeded evidence
// -----------------------------------------------------------------------------

func TestDefaultRegistry_HITLApprovalGates_CountsRows(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	tenantID := "tenant-1"
	// Seed 6 HITL decisions → above PASS threshold (5).
	for i := 0; i < 6; i++ {
		d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
			EventID:       uniqueID(t, "ev-hitl", i),
			TenantID:      tenantID,
			DecisionID:    uniqueID(t, "dec", i),
			RunID:         uniqueID(t, "run", i),
			OperatorGcid:  "op-1",
			Decision:      evidence.HitlApprove,
			AutonomyLevel: evidence.AutonomyHitlL1,
		})
		if err != nil {
			t.Fatalf("NewHITLDecision: %v", err)
		}
		if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
			t.Fatalf("AppendHITLDecision: %v", err)
		}
	}
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"fairness_and_human_oversight": {
				Items: []rubric.ConfigItem{
					{ID: "hitl", Title: "HITL", EvidenceSource: "log",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "hitl_approval_gates"},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), tenantID, "fairness_and_human_oversight")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].Status != rubric.StatusPass {
		t.Errorf("Status = %q; want PASS (6 rows >= 5 threshold)", items[0].Status)
	}
}

func TestDefaultRegistry_PolicyViolations_ZeroIsPASS(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	tenantID := "tenant-1"
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"safety_and_robustness": {
				Items: []rubric.ConfigItem{
					{ID: "safety", Title: "Safety", EvidenceSource: "log",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "content_safety_pipeline"},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), tenantID, "safety_and_robustness")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Zero violations → PASS (inverted semantics).
	if items[0].Status != rubric.StatusPass {
		t.Errorf("Status = %q; want PASS (zero violations is good)", items[0].Status)
	}
}

func TestDefaultRegistry_EvalRuns_AllPassedIsPASS(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	tenantID := "tenant-1"
	// Seed 3 non-regressed eval runs.
	for i := 0; i < 3; i++ {
		r, err := evidence.NewEvalRun(evidence.EvalRunParams{
			EventID:       uniqueID(t, "ev-eval", i),
			TenantID:      tenantID,
			RunID:         uniqueID(t, "run", i),
			AgentID:       "agt-1",
			EvalSuite:     "deepeval-quality",
			Score:         0.95,
			BaselineScore: 0.85,
		})
		if err != nil {
			t.Fatalf("NewEvalRun: %v", err)
		}
		if err := repo.AppendEvalRun(context.Background(), r); err != nil {
			t.Fatalf("AppendEvalRun: %v", err)
		}
	}
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"safety_and_robustness": {
				Items: []rubric.ConfigItem{
					{ID: "qual", Title: "Quality", EvidenceSource: "log",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "quality_evaluation"},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), tenantID, "safety_and_robustness")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].Status != rubric.StatusPass {
		t.Errorf("Status = %q; want PASS (all 3 eval runs non-regressed)", items[0].Status)
	}
}

func TestDefaultRegistry_BiasTest_AttributeFilter(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	tenantID := "tenant-1"
	// Mix demographic + other; only demographic rows should be counted.
	mix := []struct {
		attr   string
		passed bool
	}{
		{"demographic", true},
		{"demographic", true},
		{"demographic", true},
		{"language", false}, // should be ignored
	}
	for i, m := range mix {
		// Construct via Params + override Passed because NewBiasTestRun derives it.
		score := 0.9
		threshold := 0.5
		if !m.passed {
			score, threshold = 0.4, 0.5
		}
		r, err := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
			EventID:            uniqueID(t, "ev-bias", i),
			TenantID:           tenantID,
			RunID:              uniqueID(t, "run", i),
			AgentID:            "agt-1",
			ProtectedAttribute: m.attr,
			TestType:           "synthetic",
			Score:              score,
			Threshold:          threshold,
		})
		if err != nil {
			t.Fatalf("NewBiasTestRun: %v", err)
		}
		if err := repo.AppendBiasTestRun(context.Background(), r); err != nil {
			t.Fatalf("AppendBiasTestRun: %v", err)
		}
	}
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"fairness_and_human_oversight": {
				Items: []rubric.ConfigItem{
					{ID: "demo", Title: "Demographic", EvidenceSource: "log",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "demographic_bias_testing"},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), tenantID, "fairness_and_human_oversight")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// 3/3 demographic rows passed → PASS.
	if items[0].Status != rubric.StatusPass {
		t.Errorf("Status = %q; want PASS (3/3 demographic rows pass)", items[0].Status)
	}
}

func TestDefaultRegistry_CircuitBreaker_NoBreakersIsPASS(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	tenantID := "tenant-1"
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"safety_and_robustness": {
				Items: []rubric.ConfigItem{
					{ID: "cb", Title: "Circuit Breaker", EvidenceSource: "log",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "circuit_breaker"},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), tenantID, "safety_and_robustness")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].Status != rubric.StatusPass {
		t.Errorf("Status = %q; want PASS (no breakers configured)", items[0].Status)
	}
}

func TestDefaultRegistry_CircuitBreaker_OpenIsFAIL(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	tenantID := "tenant-1"
	cb := evidence.NewCircuitBreaker(tenantID, "agt-1")
	cb.TransitionTo(evidence.CircuitOpen)
	if err := repo.UpsertCircuitBreaker(context.Background(), cb); err != nil {
		t.Fatalf("UpsertCircuitBreaker: %v", err)
	}
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"safety_and_robustness": {
				Items: []rubric.ConfigItem{
					{ID: "cb", Title: "Circuit Breaker", EvidenceSource: "log",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "circuit_breaker"},
				},
			},
		},
	}
	r, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := r.Resolve(context.Background(), tenantID, "safety_and_robustness")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].Status != rubric.StatusFail {
		t.Errorf("Status = %q; want FAIL (open breaker)", items[0].Status)
	}
}
