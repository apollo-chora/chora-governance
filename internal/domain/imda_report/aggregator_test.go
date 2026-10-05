// Package imda_report_test — IMDA 4-dimension reporting aggregator + evidence
// pack tests.
//
// Per CLAUDE.md §1 + project_chora_governance_ai.md D18: IMDA Model AI
// Governance Framework with 4 fixed dimensions, all built parallel from launch
// in O+ surface.
//
// Per ADR-141 (2026-05-08) the dimension labels adopt the AssessorFlow
// o-plus-dashboard gold standard (IMDA MGF v2 + AI Verify principles):
//
//	D1 accountability                — risk classification + audit trail
//	D2 transparency                  — model cards + reasoning + decision logs
//	D3 safety_and_robustness         — guardrails + adversarial + drift
//	D4 fairness_and_human_oversight  — HITL + bias + autonomy levels
//
// Aggregator builders are named after the original CLAUDE.md §1 audience
// summaries (D1Risk* / D2Oversight* / D3CostMonitoring* / D4Transparency*)
// for source-stability; the bound dimension strings + Dimension field on the
// returned reports use the canonical labels.
package imda_report_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/imda_report"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	gcidA   = "01970000-0000-7000-9000-000000000001"
)

// thisMonth returns the reporting Period for the current calendar month.
// audit.New stamps CreatedAt = time.Now() (no settable timestamp) and the
// aggregator filters audit events by CreatedAt within the period's From/To,
// so a hardcoded month silently drops every seeded event once the calendar
// rolls past it. Anchoring on the current month keeps the audit-period tests
// deterministic across calendar boundaries.
func thisMonth(t *testing.T) imda_report.Period {
	t.Helper()
	p, err := imda_report.PeriodFromString(time.Now().UTC().Format("2006-01"))
	if err != nil {
		t.Fatalf("PeriodFromString(this month): %v", err)
	}
	return p
}

// -----------------------------------------------------------------------------
// PeriodFromString
// -----------------------------------------------------------------------------

func TestPeriodFromString_AcceptsYearMonth(t *testing.T) {
	t.Parallel()
	p, err := imda_report.PeriodFromString("2026-05")
	if err != nil {
		t.Fatalf("PeriodFromString: %v", err)
	}
	if p.From.Year() != 2026 || p.From.Month() != time.May {
		t.Errorf("From = %v; want 2026-05", p.From)
	}
	if !p.To.After(p.From) {
		t.Errorf("To should be after From: %v / %v", p.From, p.To)
	}
}

func TestPeriodFromString_AcceptsQuarter(t *testing.T) {
	t.Parallel()
	p, err := imda_report.PeriodFromString("2026-Q2")
	if err != nil {
		t.Fatalf("PeriodFromString: %v", err)
	}
	if p.From.Month() != time.April {
		t.Errorf("Q2 should start April; got %v", p.From.Month())
	}
}

func TestPeriodFromString_RejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := imda_report.PeriodFromString("foo"); err == nil {
		t.Errorf("garbage period should fail")
	}
}

// -----------------------------------------------------------------------------
// Aggregator: D1 Risk
// -----------------------------------------------------------------------------

func newSetup(t *testing.T) (*audit.InMemoryRepository, *imda.InMemoryRepository, *imda_report.Aggregator) {
	t.Helper()
	a := audit.NewInMemoryRepository()
	i := imda.NewInMemoryRepository()
	g := imda_report.NewAggregator(a, i)
	return a, i, g
}

func TestD1RiskRegister_AggregatesRiskLevelAssessments(t *testing.T) {
	t.Parallel()
	_, i, g := newSetup(t)
	ctx := context.Background()

	for _, score := range []int{40, 60, 80} {
		a, _ := imda.New(imda.NewParams{
			TenantID: tenantA, AssessorGcid: gcidA,
			Dimension: imda.DimensionRiskLevels, Score: score,
			Indicators: []string{"risk-register-current"},
		})
		_ = i.Append(ctx, a)
	}
	period, _ := imda_report.PeriodFromString("2026-05")
	rep, err := g.D1RiskRegister(ctx, tenantA, period)
	if err != nil {
		t.Fatalf("D1RiskRegister: %v", err)
	}
	if rep.AssessmentCount < 3 {
		t.Errorf("AssessmentCount = %d; want ≥3", rep.AssessmentCount)
	}
	if rep.LatestScore != 80 {
		t.Errorf("LatestScore = %d; want 80", rep.LatestScore)
	}
	if !strings.EqualFold(rep.Dimension, "accountability") {
		t.Errorf("Dimension = %q; want accountability (D1 per ADR-141)", rep.Dimension)
	}
}

// -----------------------------------------------------------------------------
// Aggregator: D2 Oversight
// -----------------------------------------------------------------------------

func TestD2Oversight_CountsHITLAndKillSwitchAuditEvents(t *testing.T) {
	t.Parallel()
	a, _, g := newSetup(t)
	ctx := context.Background()

	addAudit := func(action string, decision audit.Decision) {
		ev, err := audit.New(audit.NewParams{
			TenantID: tenantA, Gcid: gcidA,
			Action: action, Resource: "agent",
			Decision: decision,
		})
		if err != nil {
			t.Fatalf("audit.New: %v", err)
		}
		_ = a.Append(ctx, ev)
	}
	addAudit("hitl.review.approved", audit.DecisionPermitted)
	addAudit("hitl.review.denied", audit.DecisionDenied)
	addAudit("kill_switch.invoke", audit.DecisionPermitted)
	addAudit("atom.create", audit.DecisionPermitted) // unrelated

	period := thisMonth(t)
	rep, err := g.D2Oversight(ctx, tenantA, period)
	if err != nil {
		t.Fatalf("D2Oversight: %v", err)
	}
	if rep.HITLCount != 2 {
		t.Errorf("HITLCount = %d; want 2", rep.HITLCount)
	}
	if rep.KillSwitchCount != 1 {
		t.Errorf("KillSwitchCount = %d; want 1", rep.KillSwitchCount)
	}
}

// -----------------------------------------------------------------------------
// Aggregator: D3 Cost+Monitoring+Safety+Testing
// -----------------------------------------------------------------------------

func TestD3CostMonitoring_AggregatesInternalGovernance(t *testing.T) {
	t.Parallel()
	_, i, g := newSetup(t)
	ctx := context.Background()
	a, _ := imda.New(imda.NewParams{
		TenantID: tenantA, AssessorGcid: gcidA,
		Dimension: imda.DimensionInternalGovernance, Score: 75,
		Indicators: []string{"daily-cost-tracking", "safety-tests-green"},
	})
	_ = i.Append(ctx, a)

	period, _ := imda_report.PeriodFromString("2026-05")
	rep, err := g.D3CostMonitoring(ctx, tenantA, period)
	if err != nil {
		t.Fatalf("D3CostMonitoring: %v", err)
	}
	if rep.LatestScore != 75 {
		t.Errorf("LatestScore = %d; want 75", rep.LatestScore)
	}
	if len(rep.Indicators) != 2 {
		t.Errorf("Indicators = %v; want 2 entries", rep.Indicators)
	}
}

// -----------------------------------------------------------------------------
// Aggregator: D4 Transparency
// -----------------------------------------------------------------------------

func TestD4Transparency_ListsStakeholderInteractionAndDecisionLogs(t *testing.T) {
	t.Parallel()
	a, i, g := newSetup(t)
	ctx := context.Background()

	asm, _ := imda.New(imda.NewParams{
		TenantID: tenantA, AssessorGcid: gcidA,
		Dimension: imda.DimensionStakeholderInteraction, Score: 90,
		Indicators: []string{"model-card-published"},
	})
	_ = i.Append(ctx, asm)

	for i := 0; i < 3; i++ {
		ev, _ := audit.New(audit.NewParams{
			TenantID: tenantA, Gcid: gcidA,
			Action: "agent.decision.logged", Resource: "agent",
			Decision: audit.DecisionPermitted,
		})
		_ = a.Append(ctx, ev)
	}

	period := thisMonth(t)
	rep, err := g.D4Transparency(ctx, tenantA, period)
	if err != nil {
		t.Fatalf("D4Transparency: %v", err)
	}
	if rep.LatestScore != 90 {
		t.Errorf("LatestScore = %d; want 90", rep.LatestScore)
	}
	if rep.AgentDecisionLogCount < 3 {
		t.Errorf("AgentDecisionLogCount = %d; want ≥3", rep.AgentDecisionLogCount)
	}
}

// -----------------------------------------------------------------------------
// Evidence Pack Export
// -----------------------------------------------------------------------------

func TestEvidencePackExport_ReturnsMetadata(t *testing.T) {
	t.Parallel()
	a, i, g := newSetup(t)
	ctx := context.Background()

	for _, d := range imda.AllDimensions() {
		asm, _ := imda.New(imda.NewParams{
			TenantID: tenantA, AssessorGcid: gcidA,
			Dimension: d, Score: 70,
			Indicators: []string{"baseline"},
		})
		_ = i.Append(ctx, asm)
	}
	ev, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA,
		Action: "atom.create", Resource: "x",
		Decision: audit.DecisionPermitted,
	})
	_ = a.Append(ctx, ev)

	period := thisMonth(t)
	pack, err := g.ExportEvidencePack(ctx, tenantA, period, gcidA)
	if err != nil {
		t.Fatalf("ExportEvidencePack: %v", err)
	}
	if pack.PackID == "" {
		t.Errorf("PackID should be UUIDv7")
	}
	if pack.GcsURI == "" {
		t.Errorf("GcsURI should be populated (mock for MVP)")
	}
	if pack.AuditEntryCount < 1 {
		t.Errorf("AuditEntryCount = %d; want ≥1", pack.AuditEntryCount)
	}
	if pack.AssessmentCount != 4 {
		t.Errorf("AssessmentCount = %d; want 4 (one per dimension)", pack.AssessmentCount)
	}
	if pack.GeneratedByGcid != gcidA {
		t.Errorf("GeneratedByGcid = %q; want %q", pack.GeneratedByGcid, gcidA)
	}
}

func TestExportEvidencePack_RejectsEmptyTenant(t *testing.T) {
	t.Parallel()
	_, _, g := newSetup(t)
	period, _ := imda_report.PeriodFromString("2026-05")
	_, err := g.ExportEvidencePack(context.Background(), "", period, gcidA)
	if err == nil {
		t.Errorf("empty tenant should fail")
	}
}
