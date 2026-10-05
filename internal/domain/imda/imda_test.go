// Package imda_test — IMDADimensionAssessment invariants.
//
// Per CLAUDE.md §1 + project_chora_governance_ai.md D18: IMDA Model AI
// Governance Framework with 4 fixed dimensions, all built parallel from
// launch in O+ surface.
//
// Per ADR-141 (2026-05-08) the dimension labels are reconciled to the
// AssessorFlow o-plus-dashboard gold standard (IMDA MGF v2 + AI Verify
// principles): accountability / transparency / safety_and_robustness /
// fairness_and_human_oversight. The previous v1 labels (risk_levels /
// operations_management / internal_governance / stakeholder_interaction)
// remain accepted as DEPRECATED aliases for one release via Canonicalise().
package imda_test

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

const (
	tenantA    = "01970000-0000-7000-8000-000000000001"
	assessorID = "01970000-0000-7000-9000-000000000001"
)

// -----------------------------------------------------------------------------
// 4 fixed dimension names — ADR-141 canonical (IMDA MGF v2 / AI Verify)
//   D1 Accountability                — risk classification + audit trail
//   D2 Transparency                  — model cards + reasoning + decision logs
//   D3 Safety and Robustness         — guardrails + adversarial + drift
//   D4 Fairness and Human Oversight  — HITL + bias + autonomy levels
// -----------------------------------------------------------------------------

func TestDimension_AllFourFixedAreValid(t *testing.T) {
	t.Parallel()
	for _, d := range []imda.Dimension{
		imda.DimensionInternalGovernance,
		imda.DimensionRiskLevels,
		imda.DimensionOperationsManagement,
		imda.DimensionStakeholderInteraction,
	} {
		if !d.Valid() {
			t.Errorf("dimension %q should be valid", d)
		}
	}
}

// ADR-141 canonical labels MUST be valid out of the box.
func TestDimension_CanonicalLabels_AreValid(t *testing.T) {
	t.Parallel()
	for _, label := range []string{
		"accountability",
		"transparency",
		"safety_and_robustness",
		"fairness_and_human_oversight",
	} {
		if !imda.Dimension(label).Valid() {
			t.Errorf("canonical label %q should be valid", label)
		}
	}
}

// Per ADR-141 the constants now hold the canonical (gold-standard) string values.
func TestDimension_ConstantsBindToCanonicalValues(t *testing.T) {
	t.Parallel()
	cases := []struct {
		got, want imda.Dimension
		note      string
	}{
		{imda.DimensionRiskLevels, "accountability", "D1 maps to Accountability per ADR-141"},
		{imda.DimensionStakeholderInteraction, "transparency", "D2 maps to Transparency per ADR-141"},
		{imda.DimensionInternalGovernance, "safety_and_robustness", "D3 maps to Safety and Robustness per ADR-141"},
		{imda.DimensionOperationsManagement, "fairness_and_human_oversight", "D4 maps to Fairness and Human Oversight per ADR-141"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q; want %q", c.note, c.got, c.want)
		}
	}
}

// Backwards-compatible alias mode (ADR-141 §3): deprecated v1 labels MUST
// still parse via Canonicalise() for one release. A flag-day rename would
// break in-flight evidence packs and existing API consumers.
func TestDimension_Canonicalise_AcceptsDeprecatedAliases(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		// v1 deprecated → ADR-141 canonical
		"risk_levels":             "accountability",
		"operations_management":   "fairness_and_human_oversight",
		"internal_governance":     "safety_and_robustness",
		"stakeholder_interaction": "transparency",
		// canonical labels survive Canonicalise() unchanged (idempotent)
		"accountability":               "accountability",
		"transparency":                 "transparency",
		"safety_and_robustness":        "safety_and_robustness",
		"fairness_and_human_oversight": "fairness_and_human_oversight",
	}
	for in, want := range cases {
		if got := imda.Canonicalise(in); string(got) != want {
			t.Errorf("Canonicalise(%q) = %q; want %q", in, got, want)
		}
	}
}

// Canonicalise() trims whitespace + lowercases for resilience to caller noise.
func TestDimension_Canonicalise_TrimsAndLowercases(t *testing.T) {
	t.Parallel()
	if got := imda.Canonicalise("  RISK_LEVELS  "); string(got) != "accountability" {
		t.Errorf("Canonicalise trim+lowercase failed; got %q", got)
	}
}

// Unknown labels round-trip unchanged via Canonicalise (so Valid() can flag them).
func TestDimension_Canonicalise_UnknownLabels_PassThrough(t *testing.T) {
	t.Parallel()
	if got := imda.Canonicalise("totally_unknown"); string(got) != "totally_unknown" {
		t.Errorf("Canonicalise unknown should pass through; got %q", got)
	}
	if imda.Dimension("totally_unknown").Valid() {
		t.Errorf("unknown label should NOT be Valid()")
	}
}

// New() normalises deprecated aliases on construction (so persisted Assessment
// carries the canonical label only).
func TestNew_DeprecatedAlias_NormalisedToCanonical(t *testing.T) {
	t.Parallel()
	a, err := imda.New(imda.NewParams{
		TenantID:     tenantA,
		Dimension:    imda.Dimension("risk_levels"), // deprecated alias
		Score:        50,
		AssessorGcid: assessorID,
	})
	if err != nil {
		t.Fatalf("New unexpected: %v", err)
	}
	if string(a.Dimension) != "accountability" {
		t.Errorf("Assessment.Dimension = %q; want canonical %q", a.Dimension, "accountability")
	}
}

// AllDimensions returns the canonical labels in canonical order
// (Accountability / Transparency / Safety / Fairness — matches o-plus-dashboard).
func TestAllDimensions_ReturnsCanonicalOrder(t *testing.T) {
	t.Parallel()
	got := imda.AllDimensions()
	want := []imda.Dimension{
		"accountability",
		"transparency",
		"safety_and_robustness",
		"fairness_and_human_oversight",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d; want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllDimensions[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestDimension_RejectsArbitraryName(t *testing.T) {
	t.Parallel()
	for _, d := range []imda.Dimension{"foo", "", "ai_safety", "model_governance"} {
		if d.Valid() {
			t.Errorf("dimension %q should NOT be valid", d)
		}
	}
}

func TestAllDimensions_ReturnsExactlyFour(t *testing.T) {
	t.Parallel()
	if got := len(imda.AllDimensions()); got != 4 {
		t.Errorf("len(AllDimensions()) = %d; want 4 (IMDA fixed)", got)
	}
}

// -----------------------------------------------------------------------------
// New construction
// -----------------------------------------------------------------------------

func TestNew_AssignsUUIDv7AssessmentID(t *testing.T) {
	t.Parallel()
	a, err := imda.New(imda.NewParams{
		TenantID:     tenantA,
		Dimension:    imda.DimensionRiskLevels,
		Score:        85,
		Indicators:   []string{"risk-register-current"},
		AssessorGcid: assessorID,
	})
	if err != nil {
		t.Fatalf("New unexpected: %v", err)
	}
	if len(a.AssessmentID) != 36 {
		t.Errorf("AssessmentID length = %d; want 36", len(a.AssessmentID))
	}
}

func TestNew_RejectsMissingTenant(t *testing.T) {
	t.Parallel()
	_, err := imda.New(imda.NewParams{
		TenantID: "", Dimension: imda.DimensionRiskLevels, Score: 50, AssessorGcid: assessorID,
	})
	if err == nil {
		t.Errorf("expected error for missing tenant; got nil")
	}
}

func TestNew_RejectsMissingAssessor(t *testing.T) {
	t.Parallel()
	_, err := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels, Score: 50,
	})
	if err == nil {
		t.Errorf("expected error for missing assessor; got nil")
	}
}

// -----------------------------------------------------------------------------
// Score range — MUST be 0..100 inclusive
// -----------------------------------------------------------------------------

func TestNew_ScoreInRange_Boundaries(t *testing.T) {
	t.Parallel()
	for _, score := range []int{0, 1, 50, 99, 100} {
		_, err := imda.New(imda.NewParams{
			TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
			Score: score, AssessorGcid: assessorID,
		})
		if err != nil {
			t.Errorf("score=%d should be valid; got %v", score, err)
		}
	}
}

func TestNew_ScoreNegative_Rejected(t *testing.T) {
	t.Parallel()
	_, err := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
		Score: -1, AssessorGcid: assessorID,
	})
	if err == nil {
		t.Errorf("score=-1 should be rejected; got nil")
	}
}

func TestNew_ScoreOver100_Rejected(t *testing.T) {
	t.Parallel()
	_, err := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
		Score: 101, AssessorGcid: assessorID,
	})
	if err == nil {
		t.Errorf("score=101 should be rejected; got nil")
	}
}

func TestNew_RejectsInvalidDimension(t *testing.T) {
	t.Parallel()
	_, err := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: "freeform",
		Score: 50, AssessorGcid: assessorID,
	})
	if err == nil {
		t.Errorf("expected error for invalid dimension; got nil")
	}
}

func TestNew_CopiesIndicatorsDefensively(t *testing.T) {
	t.Parallel()
	indicators := []string{"i1", "i2"}
	a, _ := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
		Score: 50, Indicators: indicators, AssessorGcid: assessorID,
	})
	indicators[0] = "MUTATED"
	if a.Indicators[0] == "MUTATED" {
		t.Errorf("Indicators not defensively copied")
	}
}

// -----------------------------------------------------------------------------
// Repository — most-recent-per-dimension dashboard semantic
// -----------------------------------------------------------------------------

func TestRepository_AppendAndDashboard(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := imda.NewInMemoryRepository()

	for _, d := range imda.AllDimensions() {
		a, _ := imda.New(imda.NewParams{
			TenantID: tenantA, Dimension: d, Score: 75, AssessorGcid: assessorID,
		})
		if err := r.Append(ctx, a); err != nil {
			t.Fatalf("Append(%s) unexpected: %v", d, err)
		}
	}
	out, err := r.Dashboard(ctx, tenantA)
	if err != nil {
		t.Fatalf("Dashboard unexpected: %v", err)
	}
	if len(out) != 4 {
		t.Errorf("Dashboard returned %d dimensions; want 4", len(out))
	}
}

func TestRepository_Dashboard_ReturnsLatestPerDimension(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := imda.NewInMemoryRepository()
	old, _ := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
		Score: 30, AssessorGcid: assessorID,
	})
	_ = r.Append(ctx, old)
	newer, _ := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
		Score: 80, AssessorGcid: assessorID,
	})
	_ = r.Append(ctx, newer)

	out, _ := r.Dashboard(ctx, tenantA)
	for _, a := range out {
		if a.Dimension == imda.DimensionRiskLevels && a.Score != 80 {
			t.Errorf("Dashboard latest score = %d; want 80", a.Score)
		}
	}
}

// TestRepository_Dashboard_TieBreaksOnInsertionOrder pins the contract that
// when two assessments share an identical AssessedAt timestamp (sub-microsecond
// appends are common in test fixtures and rapid evaluator emission), the
// LATER-INSERTED assessment wins. Insertion order is the source of truth under
// tied timestamps — "latest per dimension" means last-write-wins.
//
// Pre-fix this test would fail because the previous After() tie-break left
// the earlier-inserted assessment in place when timestamps were equal.
func TestRepository_Dashboard_TieBreaksOnInsertionOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := imda.NewInMemoryRepository()

	// Two assessments with EXPLICITLY identical AssessedAt; later insertion wins.
	tied := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)

	first, _ := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
		Score: 40, AssessorGcid: assessorID,
	})
	first.AssessedAt = tied
	_ = r.Append(ctx, first)

	second, _ := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
		Score: 90, AssessorGcid: assessorID,
	})
	second.AssessedAt = tied
	_ = r.Append(ctx, second)

	out, _ := r.Dashboard(ctx, tenantA)
	var got int = -1
	for _, a := range out {
		if a.Dimension == imda.DimensionRiskLevels {
			got = a.Score
		}
	}
	if got != 90 {
		t.Errorf("under tied AssessedAt the later-inserted assessment should win; got Score=%d; want 90", got)
	}
}

func TestRepository_Dashboard_TenantIsolation(t *testing.T) {
	t.Parallel()
	tenantB := "01970000-0000-7000-8000-000000000002"
	ctx := context.Background()
	r := imda.NewInMemoryRepository()
	a, _ := imda.New(imda.NewParams{
		TenantID: tenantA, Dimension: imda.DimensionRiskLevels,
		Score: 50, AssessorGcid: assessorID,
	})
	_ = r.Append(ctx, a)
	out, _ := r.Dashboard(ctx, tenantB)
	for _, x := range out {
		if x.Score != 0 {
			t.Errorf("tenantB should not see tenantA assessments; got %v", x)
		}
	}
}
