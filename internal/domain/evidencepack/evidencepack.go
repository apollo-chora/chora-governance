// Package evidencepack assembles the IMDA D1-D4 evidence-pack ZIP that
// chora-governance exposes via POST /v1/governance/evidence/export.
//
// Per audit-platform-fillgaps.md §3.3, the pre-existing export endpoint was
// a mock that returned metadata only and never wrote a ZIP. This package
// replaces that mock with a real ZIP archive containing:
//
//	manifest.yaml                            — export metadata + signature seed
//	audit_chain.json                         — full audit-log hash-chain dump
//	D1/accountability_evidence.csv           — D1 accountability rows
//	D2/model_cards.csv                       — D2 model card index
//	D2/data_cards.csv                        — D2 data card index
//	D2/decision_explanations.csv             — D2 explanation index (auditor view)
//	D3/red_team_runs.csv                     — D3 red-team rows
//	D3/eval_runs.csv                         — D3 eval rows
//	D3/cost_anomalies.csv                    — D3 cost anomaly rows
//	D3/policy_violation_log.csv              — Tier 3 D9 policy violations
//	D3/circuit_breaker_state.csv             — D3 breaker state
//	D3/quarantine_state.csv                  — D3 quarantine state
//	D4/bias_test_runs.csv                    — D4 bias test rows
//	D4/hitl_decision_log.csv                 — D4 HITL decisions
//	model_cards/{model_id}_{version}.md      — per model-card markdown
//	data_cards/{dataset_id}_{version}.md     — per data-card markdown
//	lifecycle_stages/{stage}/.keep           — directory markers (4 stages)
//
// Long-running exports (large tenants) should run in a Cloud Run Job; the
// API layer constructs the same Exporter and writes ZIPBytes to GCS bucket
// chora-evidence-packs-{env}.
package evidencepack

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

// Exporter builds an evidence pack over the supplied repos.
type Exporter struct {
	evRepo    evidence.Repository
	auditRepo audit.Repository
}

// New constructs an Exporter.
func New(evRepo evidence.Repository, auditRepo audit.Repository) *Exporter {
	return &Exporter{evRepo: evRepo, auditRepo: auditRepo}
}

// ExportRequest is the input for a pack build.
type ExportRequest struct {
	TenantID   string
	From       time.Time
	To         time.Time
	Dimensions []string // empty = all (D1, D2, D3, D4)
}

// ExportResult is the produced pack.
type ExportResult struct {
	PackID       string
	TenantID     string
	GeneratedAt  time.Time
	From         time.Time
	To           time.Time
	ZIPBytes     []byte
	ManifestPath string
	ManifestSHA  string

	// Counts per dimension (populated for the manifest)
	CountD1 int
	CountD2 int
	CountD3 int
	CountD4 int
}

// Export assembles the pack and returns the in-memory ZIP bytes.
//
// The caller is responsible for streaming ZIPBytes to GCS (Cloud Run Job)
// and minting a signed URL with TTL 24h.
func (e *Exporter) Export(ctx context.Context, req ExportRequest) (*ExportResult, error) {
	if e == nil || e.evRepo == nil || e.auditRepo == nil {
		return nil, errors.New("evidencepack: not initialised")
	}
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errors.New("evidencepack: tenant_id is required")
	}
	if !req.From.IsZero() && !req.To.IsZero() && req.To.Before(req.From) {
		return nil, errors.New("evidencepack: to must be after from")
	}
	dims := normaliseDimensions(req.Dimensions)

	packID, err := newUUIDv7()
	if err != nil {
		return nil, fmt.Errorf("evidencepack: pack_id: %w", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Lifecycle-stage placeholders (always present)
	for _, st := range []string{"ci_pre_merge", "pre_deploy", "runtime", "post_deploy"} {
		if err := writeFile(zw, "lifecycle_stages/"+st+"/.keep", []byte("")); err != nil {
			return nil, err
		}
	}

	// Audit chain
	if err := e.writeAuditChain(ctx, zw, req); err != nil {
		return nil, err
	}

	result := &ExportResult{
		PackID:       packID,
		TenantID:     req.TenantID,
		GeneratedAt:  time.Now().UTC(),
		From:         req.From,
		To:           req.To,
		ManifestPath: "manifest.yaml",
	}

	// Filter helper
	filter := func() evidence.QueryFilter {
		f := evidence.QueryFilter{TenantID: req.TenantID}
		if !req.From.IsZero() {
			f.From = &req.From
		}
		if !req.To.IsZero() {
			f.To = &req.To
		}
		return f
	}

	// D1
	if dims["D1"] {
		rows, _ := e.evRepo.QueryAccountability(ctx, filter())
		if err := writeAccountabilityCSV(zw, rows); err != nil {
			return nil, err
		}
		result.CountD1 += len(rows)
	}

	// D2
	if dims["D2"] {
		mcs, _ := e.evRepo.QueryModelCards(ctx, filter())
		if err := writeModelCardsCSV(zw, mcs); err != nil {
			return nil, err
		}
		for _, c := range mcs {
			path := fmt.Sprintf("model_cards/%s_%s.md", sanitize(c.ModelID), sanitize(c.ModelVersion))
			if err := writeFile(zw, path, []byte(c.CardMD)); err != nil {
				return nil, err
			}
		}
		result.CountD2 += len(mcs)

		dcs, _ := e.evRepo.QueryDataCards(ctx, filter())
		if err := writeDataCardsCSV(zw, dcs); err != nil {
			return nil, err
		}
		for _, d := range dcs {
			path := fmt.Sprintf("data_cards/%s_%s.md", sanitize(d.DatasetID), sanitize(d.DatasetVersion))
			if err := writeFile(zw, path, []byte(d.CardMD)); err != nil {
				return nil, err
			}
		}
		result.CountD2 += len(dcs)

		exps, _ := e.evRepo.QueryDecisionExplanation(ctx, filter())
		if err := writeDecisionExplanationsCSV(zw, exps); err != nil {
			return nil, err
		}
		result.CountD2 += len(exps)
	}

	// D3
	if dims["D3"] {
		rts, _ := e.evRepo.QueryRedTeamRuns(ctx, filter())
		if err := writeRedTeamCSV(zw, rts); err != nil {
			return nil, err
		}
		result.CountD3 += len(rts)

		evs, _ := e.evRepo.QueryEvalRuns(ctx, filter())
		if err := writeEvalRunsCSV(zw, evs); err != nil {
			return nil, err
		}
		result.CountD3 += len(evs)

		cas, _ := e.evRepo.QueryCostAnomalies(ctx, filter())
		if err := writeCostAnomaliesCSV(zw, cas); err != nil {
			return nil, err
		}
		result.CountD3 += len(cas)

		pvs, _ := e.evRepo.QueryPolicyViolations(ctx, filter())
		if err := writePolicyViolationsCSV(zw, pvs); err != nil {
			return nil, err
		}
		result.CountD3 += len(pvs)

		cbs, _ := e.evRepo.QueryCircuitBreakers(ctx, evidence.QueryFilter{TenantID: req.TenantID})
		if err := writeCircuitBreakerCSV(zw, cbs); err != nil {
			return nil, err
		}
		result.CountD3 += len(cbs)

		qs, _ := e.evRepo.QueryQuarantines(ctx, evidence.QueryFilter{TenantID: req.TenantID})
		if err := writeQuarantineCSV(zw, qs); err != nil {
			return nil, err
		}
		result.CountD3 += len(qs)
	}

	// D4
	if dims["D4"] {
		bts, _ := e.evRepo.QueryBiasTestRuns(ctx, filter())
		if err := writeBiasTestRunsCSV(zw, bts); err != nil {
			return nil, err
		}
		result.CountD4 += len(bts)

		hds, _ := e.evRepo.QueryHITLDecisions(ctx, filter())
		if err := writeHITLDecisionsCSV(zw, hds); err != nil {
			return nil, err
		}
		result.CountD4 += len(hds)
	}

	// Manifest LAST (so it captures counts)
	manifest, manifestSHA := buildManifest(req, result)
	if err := writeFile(zw, result.ManifestPath, []byte(manifest)); err != nil {
		return nil, err
	}
	result.ManifestSHA = manifestSHA

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("evidencepack: close zip: %w", err)
	}
	result.ZIPBytes = buf.Bytes()
	return result, nil
}

// -----------------------------------------------------------------------------
// Audit chain
// -----------------------------------------------------------------------------

type auditChainEntry struct {
	EventID     string `json:"event_id"`
	TenantID    string `json:"tenant_id"`
	Action      string `json:"action"`
	Decision    string `json:"decision"`
	PrevHash    string `json:"prev_hash"`
	EntryHash   string `json:"entry_hash"`
	Traceparent string `json:"traceparent,omitempty"`
	CreatedAt   string `json:"created_at"`
}

func (e *Exporter) writeAuditChain(ctx context.Context, zw *zip.Writer, req ExportRequest) error {
	f := audit.QueryFilter{TenantID: req.TenantID}
	if !req.From.IsZero() {
		f.From = &req.From
	}
	if !req.To.IsZero() {
		f.To = &req.To
	}
	events, err := e.auditRepo.Query(ctx, f)
	if err != nil {
		return fmt.Errorf("audit query: %w", err)
	}
	out := make([]auditChainEntry, 0, len(events))
	for _, ev := range events {
		out = append(out, auditChainEntry{
			EventID:     ev.EventID,
			TenantID:    ev.TenantID,
			Action:      ev.Action,
			Decision:    string(ev.Decision),
			PrevHash:    ev.PrevHash,
			EntryHash:   ev.EntryHash,
			Traceparent: ev.Traceparent,
			CreatedAt:   ev.CreatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("audit chain marshal: %w", err)
	}
	return writeFile(zw, "audit_chain.json", body)
}

// -----------------------------------------------------------------------------
// Manifest (lightweight YAML mirror — no full yaml lib needed)
// -----------------------------------------------------------------------------

func buildManifest(req ExportRequest, r *ExportResult) (string, string) {
	var b strings.Builder
	b.WriteString("# IMDA Evidence Pack Manifest\n")
	b.WriteString("# Generated by chora-governance per ADR-141 + audit-platform-fillgaps.md §5\n")
	b.WriteString("\n")
	b.WriteString("pack_id: " + r.PackID + "\n")
	b.WriteString("tenant_id: " + req.TenantID + "\n")
	b.WriteString("generated_at: " + r.GeneratedAt.Format(time.RFC3339) + "\n")
	if !req.From.IsZero() {
		b.WriteString("period_from: " + req.From.UTC().Format(time.RFC3339) + "\n")
	} else {
		b.WriteString("period_from: \"\"\n")
	}
	if !req.To.IsZero() {
		b.WriteString("period_to: " + req.To.UTC().Format(time.RFC3339) + "\n")
	} else {
		b.WriteString("period_to: \"\"\n")
	}
	b.WriteString("schema_version: 1\n")
	b.WriteString("evidence_count_d1: " + strconv.Itoa(r.CountD1) + "\n")
	b.WriteString("evidence_count_d2: " + strconv.Itoa(r.CountD2) + "\n")
	b.WriteString("evidence_count_d3: " + strconv.Itoa(r.CountD3) + "\n")
	b.WriteString("evidence_count_d4: " + strconv.Itoa(r.CountD4) + "\n")
	b.WriteString("dimensions:\n")
	for _, d := range []string{"D1", "D2", "D3", "D4"} {
		b.WriteString("  - " + d + "\n")
	}
	b.WriteString("imda_canonical_labels:\n")
	b.WriteString("  D1: accountability\n")
	b.WriteString("  D2: transparency\n")
	b.WriteString("  D3: safety_and_robustness\n")
	b.WriteString("  D4: fairness_and_human_oversight\n")
	b.WriteString("lifecycle_stages:\n")
	for _, s := range []string{"ci_pre_merge", "pre_deploy", "runtime", "post_deploy"} {
		b.WriteString("  - " + s + "\n")
	}

	body := b.String()
	sum := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(sum[:])
	body += "manifest_sha256: " + hash + "\n"
	return body, hash
}

// -----------------------------------------------------------------------------
// CSV writers (one per evidence shape)
// -----------------------------------------------------------------------------

func writeAccountabilityCSV(zw *zip.Writer, rows []*evidence.AccountabilityEvidence) error {
	w, err := zw.Create("D1/accountability_evidence.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"event_id", "tenant_id", "agent_id", "owner_gcid", "decision_id",
		"decision_type", "evidence_hash", "lifecycle_stage", "recorded_at",
	}); err != nil {
		return err
	}
	for _, r := range rows {
		if err := cw.Write([]string{
			r.EventID, r.TenantID, r.AgentID, r.OwnerGcid, r.DecisionID,
			r.DecisionType, r.EvidenceHash, string(r.LifecycleStage),
			r.RecordedAt.UTC().Format(time.RFC3339Nano),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeModelCardsCSV(zw *zip.Writer, rows []*evidence.ModelCard) error {
	w, err := zw.Create("D2/model_cards.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "model_id", "model_version", "intended_uses", "lifecycle_stage", "registered_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.ModelID, r.ModelVersion, r.IntendedUses,
			string(r.LifecycleStage),
			r.RegisteredAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeDataCardsCSV(zw *zip.Writer, rows []*evidence.DataCard) error {
	w, err := zw.Create("D2/data_cards.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "dataset_id", "dataset_version", "provenance", "lifecycle_stage", "registered_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.DatasetID, r.DatasetVersion, r.Provenance,
			string(r.LifecycleStage),
			r.RegisteredAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeDecisionExplanationsCSV(zw *zip.Writer, rows []*evidence.DecisionExplanation) error {
	w, err := zw.Create("D2/decision_explanations.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "decision_id", "audience", "confidence_score", "lifecycle_stage", "generated_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.DecisionID, string(r.Audience),
			strconv.FormatFloat(r.ConfidenceScore, 'f', 4, 64),
			string(r.LifecycleStage),
			r.GeneratedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeRedTeamCSV(zw *zip.Writer, rows []*evidence.RedTeamRun) error {
	w, err := zw.Create("D3/red_team_runs.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "run_id", "agent_id", "verdict", "lifecycle_stage", "run_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.RunID, r.AgentID, r.Verdict,
			string(r.LifecycleStage),
			r.RunAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeEvalRunsCSV(zw *zip.Writer, rows []*evidence.EvalRun) error {
	w, err := zw.Create("D3/eval_runs.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "run_id", "agent_id", "eval_suite", "score", "baseline_score", "regressed", "lifecycle_stage", "run_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.RunID, r.AgentID, r.EvalSuite,
			strconv.FormatFloat(r.Score, 'f', 4, 64),
			strconv.FormatFloat(r.BaselineScore, 'f', 4, 64),
			strconv.FormatBool(r.Regressed),
			string(r.LifecycleStage),
			r.RunAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeCostAnomaliesCSV(zw *zip.Writer, rows []*evidence.CostAnomaly) error {
	w, err := zw.Create("D3/cost_anomalies.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "anomaly_id", "agent_id", "baseline_micros", "observed_micros", "sigma_factor", "lifecycle_stage", "recorded_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.AnomalyID, r.AgentID,
			strconv.FormatInt(r.BaselineMicros, 10),
			strconv.FormatInt(r.ObservedMicros, 10),
			strconv.FormatFloat(r.SigmaFactor, 'f', 4, 64),
			string(r.LifecycleStage),
			r.RecordedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writePolicyViolationsCSV(zw *zip.Writer, rows []*evidence.PolicyViolation) error {
	w, err := zw.Create("D3/policy_violation_log.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "agent_id", "policy_name", "severity", "detector", "lifecycle_stage", "detected_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.AgentID, r.PolicyName, r.Severity, r.Detector,
			string(r.LifecycleStage),
			r.DetectedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeCircuitBreakerCSV(zw *zip.Writer, rows []*evidence.CircuitBreaker) error {
	w, err := zw.Create("D3/circuit_breaker_state.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"tenant_id", "agent_id", "state", "failure_count", "last_transitioned_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.TenantID(), r.AgentID(), string(r.State()),
			strconv.Itoa(r.FailureCount()),
			r.LastTransitionedAt().UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeQuarantineCSV(zw *zip.Writer, rows []*evidence.Quarantine) error {
	w, err := zw.Create("D3/quarantine_state.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"tenant_id", "agent_id", "reason", "quarantined_at", "released_at"})
	for _, r := range rows {
		released := ""
		if r.ReleasedAt != nil {
			released = r.ReleasedAt.UTC().Format(time.RFC3339Nano)
		}
		cw.Write([]string{
			r.TenantID, r.AgentID, r.Reason,
			r.QuarantinedAt.UTC().Format(time.RFC3339Nano),
			released,
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeBiasTestRunsCSV(zw *zip.Writer, rows []*evidence.BiasTestRun) error {
	w, err := zw.Create("D4/bias_test_runs.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "run_id", "agent_id", "protected_attribute", "test_type", "score", "threshold", "passed", "lifecycle_stage", "run_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.RunID, r.AgentID,
			r.ProtectedAttribute, r.TestType,
			strconv.FormatFloat(r.Score, 'f', 4, 64),
			strconv.FormatFloat(r.Threshold, 'f', 4, 64),
			strconv.FormatBool(r.Passed),
			string(r.LifecycleStage),
			r.RunAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

func writeHITLDecisionsCSV(zw *zip.Writer, rows []*evidence.HITLDecision) error {
	w, err := zw.Create("D4/hitl_decision_log.csv")
	if err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Write([]string{"event_id", "tenant_id", "decision_id", "run_id", "operator_gcid", "decision", "autonomy_level", "lifecycle_stage", "decided_at"})
	for _, r := range rows {
		cw.Write([]string{
			r.EventID, r.TenantID, r.DecisionID, r.RunID, r.OperatorGcid,
			string(r.Decision), string(r.AutonomyLevel),
			string(r.LifecycleStage),
			r.DecidedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	cw.Flush()
	return cw.Error()
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func writeFile(zw *zip.Writer, name string, body []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("zip create %s: %w", name, err)
	}
	if _, err := io.Copy(w, bytes.NewReader(body)); err != nil {
		return fmt.Errorf("zip write %s: %w", name, err)
	}
	return nil
}

func normaliseDimensions(in []string) map[string]bool {
	out := map[string]bool{}
	if len(in) == 0 {
		out["D1"] = true
		out["D2"] = true
		out["D3"] = true
		out["D4"] = true
		return out
	}
	for _, d := range in {
		v := strings.ToUpper(strings.TrimSpace(d))
		if v != "" {
			out[v] = true
		}
	}
	// Defensive: ensure stable iteration order in tests
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return out
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", " ", "_", string(filepathSep), "_")
	return r.Replace(s)
}

const filepathSep = '/'

func newUUIDv7() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
