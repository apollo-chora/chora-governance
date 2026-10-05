// Package evidencepack — RED tests for the IMDA evidence-pack ZIP exporter.
//
// Per audit-platform-fillgaps.md §3.3, the existing evidence-pack export is
// a mock that returns metadata only and never writes a ZIP. This package
// replaces that mock with a real archive containing per-dimension CSVs +
// model/data card markdown + audit_chain.json + manifest.yaml.
package evidencepack_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/evidencepack"
)

func newRepoWithSeedData(t *testing.T) (evidence.Repository, audit.Repository) {
	t.Helper()
	er := evidence.NewInMemoryRepository()
	ar := audit.NewInMemoryRepository()
	ctx := context.Background()

	// D1 row
	a1, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID:  "11111111-1111-1111-1111-111111111111",
		TenantID: "tenant-1",
		AgentID:  "agent-router", OwnerGcid: "owner-1",
		DecisionID: "dec-1", DecisionType: "route_to_gemini",
		Provenance: map[string]any{"reason": "intent=qna"},
	})
	er.AppendAccountability(ctx, a1)

	// D2 model card
	mc, _ := evidence.NewModelCard(evidence.ModelCardParams{
		EventID:  "22222222-2222-2222-2222-222222222222",
		TenantID: "tenant-1",
		ModelID:  "gemini-2.5-flash", ModelVersion: "v1",
		CardMD:       "# Gemini Card\n",
		IntendedUses: "RAG QA",
	})
	er.AppendModelCard(ctx, mc)

	// D2 data card
	dc, _ := evidence.NewDataCard(evidence.DataCardParams{
		EventID:   "33333333-3333-3333-3333-333333333333",
		TenantID:  "tenant-1",
		DatasetID: "rag-corpus", DatasetVersion: "2026-05",
		CardMD: "# RAG corpus\n",
	})
	er.AppendDataCard(ctx, dc)

	// D2 explanation row
	ex, _ := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
		EventID:  "44444444-4444-4444-4444-444444444444",
		TenantID: "tenant-1", DecisionID: "dec-1",
		Audience: evidence.AudienceLearner, ExplanationMD: "Why this atom?",
		ConfidenceScore: 0.9,
	})
	er.AppendDecisionExplanation(ctx, ex)

	// D3 red-team
	rt, _ := evidence.NewRedTeamRun(evidence.RedTeamRunParams{
		EventID:  "55555555-5555-5555-5555-555555555555",
		TenantID: "tenant-1", RunID: "rt-1",
		AgentID: "agent-router", Verdict: "pass",
	})
	er.AppendRedTeamRun(ctx, rt)

	// D3 eval
	ev, _ := evidence.NewEvalRun(evidence.EvalRunParams{
		EventID:  "66666666-6666-6666-6666-666666666666",
		TenantID: "tenant-1", RunID: "ev-1",
		AgentID: "agent-router", EvalSuite: "deepeval",
		Score: 0.92, BaselineScore: 0.88,
	})
	er.AppendEvalRun(ctx, ev)

	// D3 cost anomaly
	ca, _ := evidence.NewCostAnomaly(evidence.CostAnomalyParams{
		EventID:  "77777777-7777-7777-7777-777777777777",
		TenantID: "tenant-1", AnomalyID: "an-1",
		AgentID:        "agent-router",
		BaselineMicros: 1000, ObservedMicros: 5000, SigmaFactor: 4.0,
	})
	er.AppendCostAnomaly(ctx, ca)

	// D3 policy violation
	pv, _ := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
		EventID:  "88888888-8888-8888-8888-888888888888",
		TenantID: "tenant-1", AgentID: "agent-router",
		PolicyName: "no_pii", Severity: "high", Detector: "cloud_dlp",
	})
	er.AppendPolicyViolation(ctx, pv)

	// D4 bias
	bt, _ := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
		EventID:  "99999999-9999-9999-9999-999999999999",
		TenantID: "tenant-1", RunID: "bt-1",
		AgentID:            "agent-router",
		ProtectedAttribute: "gender", TestType: "demographic_parity",
		Score: 0.95, Threshold: 0.8,
	})
	er.AppendBiasTestRun(ctx, bt)

	// D4 HITL
	hd, _ := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID:  "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		TenantID: "tenant-1", DecisionID: "dec-1", RunID: "run-1",
		OperatorGcid: "op-1",
		Decision:     evidence.HitlApprove, AutonomyLevel: evidence.AutonomyHotl,
	})
	er.AppendHITLDecision(ctx, hd)

	// Audit chain entry
	ae, _ := audit.New(audit.NewParams{
		TenantID: "tenant-1", Gcid: "user-1", Action: "policy.update",
		Decision: audit.DecisionPermitted, Reason: "test",
	})
	ar.Append(ctx, ae)

	return er, ar
}

func TestExporter_Export_ProducesZIP(t *testing.T) {
	er, ar := newRepoWithSeedData(t)
	exp := evidencepack.New(er, ar)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)

	out, err := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "tenant-1",
		From:     from,
		To:       to,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if out.PackID == "" {
		t.Error("PackID must be populated")
	}
	if len(out.ZIPBytes) == 0 {
		t.Fatal("ZIPBytes must be populated")
	}
	if out.ManifestPath == "" {
		t.Error("ManifestPath must be populated")
	}
}

func TestExporter_ZIPContainsAllExpectedEntries(t *testing.T) {
	er, ar := newRepoWithSeedData(t)
	exp := evidencepack.New(er, ar)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)

	out, err := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "tenant-1",
		From:     from,
		To:       to,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}

	expected := []string{
		"manifest.yaml",
		"audit_chain.json",
		"D1/accountability_evidence.csv",
		"D2/model_cards.csv",
		"D2/data_cards.csv",
		"D2/decision_explanations.csv",
		"D3/red_team_runs.csv",
		"D3/eval_runs.csv",
		"D3/cost_anomalies.csv",
		"D3/policy_violation_log.csv",
		"D3/circuit_breaker_state.csv",
		"D3/quarantine_state.csv",
		"D4/bias_test_runs.csv",
		"D4/hitl_decision_log.csv",
		// model card files (per card)
		"model_cards/gemini-2.5-flash_v1.md",
		// data card files
		"data_cards/rag-corpus_2026-05.md",
	}
	have := make(map[string]bool)
	for _, f := range zr.File {
		have[f.Name] = true
	}
	for _, want := range expected {
		if !have[want] {
			t.Errorf("ZIP missing entry: %q", want)
		}
	}
}

func TestExporter_ManifestContainsTenantAndPeriod(t *testing.T) {
	er, ar := newRepoWithSeedData(t)
	exp := evidencepack.New(er, ar)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)

	out, err := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "tenant-1",
		From:     from,
		To:       to,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	for _, f := range zr.File {
		if f.Name != "manifest.yaml" {
			continue
		}
		rc, _ := f.Open()
		defer rc.Close()
		body, _ := io.ReadAll(rc)
		s := string(body)
		if !strings.Contains(s, "tenant_id: tenant-1") {
			t.Errorf("manifest missing tenant: %s", s)
		}
		if !strings.Contains(s, "period_from:") {
			t.Errorf("manifest missing period_from")
		}
		if !strings.Contains(s, "pack_id:") {
			t.Errorf("manifest missing pack_id")
		}
		if !strings.Contains(s, "evidence_count_d1:") {
			t.Errorf("manifest missing evidence count")
		}
	}
}

func TestExporter_AuditChainEntries(t *testing.T) {
	er, ar := newRepoWithSeedData(t)
	exp := evidencepack.New(er, ar)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)

	out, _ := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "tenant-1",
		From:     from,
		To:       to,
	})
	zr, _ := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	for _, f := range zr.File {
		if f.Name != "audit_chain.json" {
			continue
		}
		rc, _ := f.Open()
		body, _ := io.ReadAll(rc)
		rc.Close()
		s := string(body)
		if !strings.Contains(s, "entry_hash") {
			t.Errorf("audit_chain.json missing entry_hash")
		}
	}
}

func TestExporter_FilterByDimensions(t *testing.T) {
	er, ar := newRepoWithSeedData(t)
	exp := evidencepack.New(er, ar)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)

	// Request only D1 — D2/D3/D4 dirs should be absent
	out, _ := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID:   "tenant-1",
		From:       from,
		To:         to,
		Dimensions: []string{"D1"},
	})
	zr, _ := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	hasD1 := false
	hasD2 := false
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "D1/") {
			hasD1 = true
		}
		if strings.HasPrefix(f.Name, "D2/") {
			hasD2 = true
		}
	}
	if !hasD1 {
		t.Error("filtered D1 export missing D1 dir")
	}
	if hasD2 {
		t.Error("filtered D1 export should not include D2 dir")
	}
}

func TestExporter_RequiresTenantID(t *testing.T) {
	er, ar := newRepoWithSeedData(t)
	exp := evidencepack.New(er, ar)
	if _, err := exp.Export(context.Background(), evidencepack.ExportRequest{}); err == nil {
		t.Error("expected error on missing tenant_id")
	}
}

func TestExporter_RequiresFromBeforeTo(t *testing.T) {
	er, ar := newRepoWithSeedData(t)
	exp := evidencepack.New(er, ar)
	from := time.Now().UTC().Add(time.Hour)
	to := time.Now().UTC().Add(-time.Hour) // inverted
	if _, err := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "tenant-1", From: from, To: to,
	}); err == nil {
		t.Error("expected error on inverted period")
	}
}

func TestExporter_LifecycleStageDirectoryPresent(t *testing.T) {
	er, ar := newRepoWithSeedData(t)
	exp := evidencepack.New(er, ar)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)

	out, _ := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "tenant-1", From: from, To: to,
	})
	zr, _ := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	have := map[string]bool{}
	for _, f := range zr.File {
		have[f.Name] = true
	}
	// ci_pre_merge / pre_deploy / runtime / post_deploy directory markers
	for _, st := range []string{
		"lifecycle_stages/ci_pre_merge/.keep",
		"lifecycle_stages/pre_deploy/.keep",
		"lifecycle_stages/runtime/.keep",
		"lifecycle_stages/post_deploy/.keep",
	} {
		if !have[st] {
			t.Errorf("ZIP missing lifecycle stage marker: %q", st)
		}
	}
}
