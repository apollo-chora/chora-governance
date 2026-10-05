// tail_internal_test.go — INTERNAL (package imda_report) coverage tail:
// PeriodFromString helper branches + aggregator error paths (empty tenant,
// dashboard error, audit query error).
//
// The external aggregator_test.go covers the happy paths; the helper parse
// functions + repo-error branches are only reachable internally.
package imda_report

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

func TestInternal_PeriodFromString_Branches(t *testing.T) {
	t.Parallel()
	if _, err := PeriodFromString(""); err == nil {
		t.Error("empty label should error")
	}
	if _, err := PeriodFromString("not-a-year"); err == nil {
		t.Error("bad year should error")
	}
	// year out of range (< 2000)
	if _, err := PeriodFromString("1999"); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("1999 err = %v; want out-of-range", err)
	}

	// quarter branches
	if _, err := PeriodFromString("2026-QX"); err == nil {
		t.Error("alpha quarter should error")
	}
	if _, err := PeriodFromString("2026-Q0"); err == nil {
		t.Error("Q0 out of range should error")
	}
	if _, err := PeriodFromString("2026-Q5"); err == nil {
		t.Error("Q5 out of range should error")
	}
	if p, err := PeriodFromString("2026-Q2"); err != nil || p.From.Month() != time.April {
		t.Errorf("2026-Q2 = %+v err=%v; want April start", p, err)
	}

	// month branches
	if _, err := PeriodFromString("2026-13"); err == nil {
		t.Error("month 13 should error")
	}
	if _, err := PeriodFromString("2026-00"); err == nil {
		t.Error("month 00 should error")
	}
	if _, err := PeriodFromString("2026-abc"); err == nil {
		t.Error("alpha month should error")
	}
	if p, err := PeriodFromString("2026-05"); err != nil || p.From.Month() != time.May || p.Label != "2026-05" {
		t.Errorf("2026-05 = %+v err=%v; want May start", p, err)
	}

	// three segments → unrecognised
	if _, err := PeriodFromString("2026-05-01"); err == nil {
		t.Error("three segments should error")
	}
}

type errIMDA struct {
	*imda.InMemoryRepository
	errDashboard bool
}

func (f *errIMDA) Dashboard(context.Context, string) ([]*imda.Assessment, error) {
	if f.errDashboard {
		return nil, errors.New("dashboard boom")
	}
	return f.InMemoryRepository.Dashboard(context.Background(), "unused")
}

type errAuditForReport struct {
	*audit.InMemoryRepository
	errQuery bool
}

func (f *errAuditForReport) Query(ctx context.Context, filter audit.QueryFilter) ([]*audit.Event, error) {
	if f.errQuery {
		return nil, errors.New("query boom")
	}
	return f.InMemoryRepository.Query(ctx, filter)
}

func TestInternal_Aggregator_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	period := Period{Label: "2026-Q1", From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}

	// empty tenant → all four builders + export reject
	g := NewAggregator(audit.NewInMemoryRepository(), imda.NewInMemoryRepository())
	if _, err := g.D1RiskRegister(ctx, "", period); err == nil {
		t.Error("D1 empty tenant should error")
	}
	if _, err := g.D2Oversight(ctx, "", period); err == nil {
		t.Error("D2 empty tenant should error")
	}
	if _, err := g.D3CostMonitoring(ctx, "", period); err == nil {
		t.Error("D3 empty tenant should error")
	}
	if _, err := g.D4Transparency(ctx, "", period); err == nil {
		t.Error("D4 empty tenant should error")
	}
	if _, err := g.ExportEvidencePack(ctx, "", period, "g1"); err == nil {
		t.Error("export empty tenant should error")
	}

	// dashboard error → D1/D3/D4/export wrap it
	errRepo := &errIMDA{InMemoryRepository: imda.NewInMemoryRepository(), errDashboard: true}
	g = NewAggregator(audit.NewInMemoryRepository(), errRepo)
	if _, err := g.D1RiskRegister(ctx, "t1", period); err == nil {
		t.Error("D1 dashboard error should propagate")
	}
	if _, err := g.D3CostMonitoring(ctx, "t1", period); err == nil {
		t.Error("D3 dashboard error should propagate")
	}
	if _, err := g.D4Transparency(ctx, "t1", period); err == nil {
		t.Error("D4 dashboard error should propagate")
	}
	if _, err := g.ExportEvidencePack(ctx, "t1", period, "g1"); err == nil {
		t.Error("export dashboard error should propagate")
	}

	// audit query error → D2 / D4 / export wrap it
	errAudit := &errAuditForReport{InMemoryRepository: audit.NewInMemoryRepository(), errQuery: true}
	g = NewAggregator(errAudit, imda.NewInMemoryRepository())
	if _, err := g.D2Oversight(ctx, "t1", period); err == nil {
		t.Error("D2 audit error should propagate")
	}
	if _, err := g.D4Transparency(ctx, "t1", period); err == nil {
		t.Error("D4 audit error should propagate")
	}
	if _, err := g.ExportEvidencePack(ctx, "t1", period, "g1"); err == nil {
		t.Error("export audit error should propagate")
	}
}

func TestInternal_D2Oversight_AuditPrefixes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	per := Period{Label: "2026", From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	auditRepo := audit.NewInMemoryRepository()
	ev, err := audit.New(audit.NewParams{TenantID: "t1", Gcid: "g1", Action: "hitl.claimed", Decision: audit.DecisionPermitted})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	if err := auditRepo.Append(ctx, ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	ev2, _ := audit.New(audit.NewParams{TenantID: "t1", Gcid: "g1", Action: "kill_switch.engaged", Decision: audit.DecisionPermitted})
	if err := auditRepo.Append(ctx, ev2); err != nil {
		t.Fatalf("Append: %v", err)
	}
	g := NewAggregator(auditRepo, imda.NewInMemoryRepository())
	rep, err := g.D2Oversight(ctx, "t1", per)
	if err != nil {
		t.Fatalf("D2Oversight: %v", err)
	}
	if rep.HITLCount != 1 || rep.KillSwitchCount != 1 {
		t.Errorf("HITLCount=%d KillSwitchCount=%d; want 1/1", rep.HITLCount, rep.KillSwitchCount)
	}
}

func TestInternal_D4Transparency_CountsAndModelCards(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	per := Period{Label: "2026", From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	auditRepo := audit.NewInMemoryRepository()
	ev, _ := audit.New(audit.NewParams{TenantID: "t1", Gcid: "g1", Action: "agent.decision.logged", Decision: audit.DecisionPermitted})
	if err := auditRepo.Append(ctx, ev); err != nil {
		t.Fatalf("Append: %v", err)
	}
	imdaRepo := imda.NewInMemoryRepository()
	a, err := imda.New(imda.NewParams{TenantID: "t1", Dimension: imda.DimensionStakeholderInteraction, Score: 77,
		Indicators: []string{"model-card: v1", "transparency-report"}, AssessorGcid: "g1"})
	if err != nil {
		t.Fatalf("imda.New: %v", err)
	}
	if err := imdaRepo.Append(ctx, a); err != nil {
		t.Fatalf("Append: %v", err)
	}
	g := NewAggregator(auditRepo, imdaRepo)
	rep, err := g.D4Transparency(ctx, "t1", per)
	if err != nil {
		t.Fatalf("D4Transparency: %v", err)
	}
	if rep.LatestScore != 77 {
		t.Errorf("LatestScore = %d; want 77", rep.LatestScore)
	}
	if len(rep.ModelCards) != 1 || rep.AgentDecisionLogCount != 1 {
		t.Errorf("ModelCards=%v AgentDecisionLogCount=%d; want 1 card + 1 count", rep.ModelCards, rep.AgentDecisionLogCount)
	}
}

func TestInternal_D1RiskRegister_NoDimensionAssessment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	g := NewAggregator(audit.NewInMemoryRepository(), imda.NewInMemoryRepository())
	rep, err := g.D1RiskRegister(ctx, "t1", Period{Label: "2026"})
	if err != nil {
		t.Fatalf("D1RiskRegister: %v", err)
	}
	if rep.LatestScore != 0 || rep.AssessmentCount != 3 {
		t.Errorf("no assessment: score=%d count=%d", rep.LatestScore, rep.AssessmentCount)
	}
}
