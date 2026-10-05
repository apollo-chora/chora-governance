// evidence_repository.go — pgx-backed implementation of evidence.Repository.
//
// Schema: 12 IMDA D1-D4 evidence tables in migration 0003_imda_evidence.sql.
// 10 of the 12 (accountability_evidence, model_card_registry, data_card_registry,
// decision_explanation, red_team_runs, eval_runs, cost_anomalies,
// bias_test_runs, hitl_decision_log, policy_violation_log) are APPEND-ONLY —
// the trigger trg_*_no_update / trg_*_no_delete rejects UPDATE + DELETE at
// the DB layer; this adapter mirrors that contract and NEVER attempts
// UPDATE/DELETE. Re-delivery from at-least-once Pub/Sub is handled by
// catching the unique-violation on event_id and returning nil (idempotent).
//
// circuit_breaker_state + quarantine_state are state machines (UPDATE
// allowed) — Upsert uses ON CONFLICT (tenant_id, agent_id) DO UPDATE.
//
// All tenant-scoped tables are RLS-protected by the chora.tenant_id session
// var (migration 0003 lines 491-541) with a `current_setting('chora.tenant_id',
// true)::uuid` policy. EVERY Append*/Query*/Upsert*/Load*/Update* method here
// therefore runs inside TenantTxQuerier.WithTenantTx, which issues
// `SET LOCAL chora.tenant_id = <tenant>` on the transaction BEFORE the
// statement. The GUC value is the row's own tenant (writes) or the filter's
// tenant (reads), normalised via NormalizeTenantForRLS so the "platform"
// envelope sentinel maps to the nil UUID the `::uuid` cast accepts.
//
// Historical defect (fixed here): these methods previously ran on the bare
// pool with NO GUC, so every evidence INSERT was rejected
// ("new row violates row-level security policy for table
// accountability_evidence") → NACK → dead-letter → dropped, and the IMDA
// dashboard read 0% / AWAITING DATA. Mirrors the chora-observability
// decision_repository WithTenantTx fix.
package pg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

// EvidenceRepository is the pgx-backed implementation of evidence.Repository.
//
// q is a TenantTxQuerier (not the bare Querier) because every evidence table
// is RLS-protected on the chora.tenant_id GUC — see the package godoc.
type EvidenceRepository struct {
	q TenantTxQuerier
}

// NewEvidenceRepository constructs an EvidenceRepository backed by the
// supplied TenantTxQuerier (typically PgxPoolQuerier).
func NewEvidenceRepository(q TenantTxQuerier) *EvidenceRepository {
	return &EvidenceRepository{q: q}
}

// -----------------------------------------------------------------------------
// Shared filter builder
// -----------------------------------------------------------------------------

// filterBuilder accumulates WHERE clauses + args for evidence Query* methods.
type filterBuilder struct {
	sql  string
	args []any
	idx  int
}

func newFilter() *filterBuilder { return &filterBuilder{} }

// rlsScopeFilter normalises f.TenantID ("platform"/"" → NilTenantUUID) so the
// WHERE-clause `tenant_id = $N::uuid` predicate matches the SET LOCAL
// chora.tenant_id GUC value. Without this the in-clause predicate could carry
// the un-castable 'platform' literal while the GUC carries the nil UUID.
// Returns a copy; never mutates the caller's filter.
func rlsScopeFilter(f evidence.QueryFilter) evidence.QueryFilter {
	if f.TenantID != "" {
		f.TenantID = NormalizeTenantForRLS(f.TenantID)
	}
	return f
}

// tenantForFilter returns the tenant id to apply via SET LOCAL chora.tenant_id
// for a read scoped by f. An empty filter tenant maps to NilTenantUUID so the
// transaction still scopes to platform-level rows (and never trips the
// empty-tenant SET LOCAL guard). Callers should rlsScopeFilter(f) first so the
// WHERE predicate agrees with the GUC.
func tenantForFilter(f evidence.QueryFilter) string {
	return NormalizeTenantForRLS(f.TenantID)
}

// scanRowsTx runs sql/args inside WithTenantTx (so RLS-protected evidence
// reads pass the chora.tenant_id policy), then collects one T per row via
// scan. The whole iteration runs inside the tx — Rows are fully consumed
// before the tx closes. label prefixes wrapped errors (e.g.
// "evidence.QueryRedTeamRuns"). tenantID must already be normalised.
func scanRowsTx[T any](
	ctx context.Context,
	q TenantTxQuerier,
	tenantID string,
	sql string,
	args []any,
	label string,
	scan func(Rows) (T, error),
) ([]T, error) {
	out := []T{}
	err := q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scan(rows)
			if err != nil {
				return fmt.Errorf("%s: scan: %w", label, err)
			}
			out = append(out, v)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("%s: iter: %w", label, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (b *filterBuilder) add(v any) string {
	b.idx++
	b.args = append(b.args, v)
	return fmt.Sprintf("$%d", b.idx)
}

// applyCommon adds tenant_id + lifecycle_stage + agent_id filters using the
// supplied column name for the agent column (which differs by table).
func (b *filterBuilder) applyCommon(f evidence.QueryFilter, agentCol string) {
	if f.TenantID != "" {
		b.sql += " AND tenant_id = " + b.add(f.TenantID) + "::uuid"
	}
	if f.LifecycleStage != "" {
		b.sql += " AND lifecycle_stage = " + b.add(string(f.LifecycleStage)) + "::imda_lifecycle_stage"
	}
	if agentCol != "" && f.AgentID != "" {
		b.sql += " AND " + agentCol + " = " + b.add(f.AgentID)
	}
}

// applyTimeRange + pagination for the supplied time column.
func (b *filterBuilder) applyTimeAndPage(f evidence.QueryFilter, timeCol string) {
	if f.From != nil {
		b.sql += " AND " + timeCol + " >= " + b.add(*f.From)
	}
	if f.To != nil {
		b.sql += " AND " + timeCol + " <= " + b.add(*f.To)
	}
	b.sql += " ORDER BY " + timeCol + " DESC"
	if f.Limit > 0 {
		b.sql += " LIMIT " + b.add(f.Limit)
	}
	if f.Offset > 0 {
		b.sql += " OFFSET " + b.add(f.Offset)
	}
}

// isAppendOnlyDuplicate returns true if err looks like a unique-violation
// on event_id — which is the idempotent path for at-least-once re-delivery.
func isAppendOnlyDuplicate(err error) bool {
	return isUniqueViolation(err)
}

// jsonbArg serialises m to JSON for a JSONB column. Returns "{}" for nil/empty.
func jsonbArg(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// nullableUUIDArg maps a Go string into a pgx-bindable arg for a nullable
// UUID column: a blank-after-trim string becomes SQL NULL (nil *string), a
// non-blank value passes through. Used for hitl_decision_log.operator_gcid,
// which is NULL on a PENDING gate (no operator decided yet) per migration
// 0010 — binding "" would fail the ::uuid cast.
func nullableUUIDArg(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return &v
}

// =============================================================================
// D1 — AccountabilityEvidence
// =============================================================================

func (r *EvidenceRepository) AppendAccountability(ctx context.Context, e *evidence.AccountabilityEvidence) error {
	if e == nil {
		return errors.New("evidence.AppendAccountability: nil")
	}
	const q = `INSERT INTO accountability_evidence (
		event_id, tenant_id, agent_id, owner_gcid,
		decision_id, decision_type, decision_provenance,
		evidence_hash, lifecycle_stage, traceparent, recorded_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4::uuid,
		$5, $6, $7::jsonb,
		$8, $9::imda_lifecycle_stage, NULLIF($10,''), $11
	)`
	// tenant normalised ("platform"/"" → NilTenantUUID) so it satisfies the
	// UUID column AND matches the SET LOCAL chora.tenant_id GUC the RLS policy
	// checks against the row being inserted.
	tenantID := NormalizeTenantForRLS(e.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			e.EventID, tenantID, e.AgentID, e.OwnerGcid,
			e.DecisionID, e.DecisionType, jsonbArg(e.Provenance),
			e.EvidenceHash, string(e.LifecycleStage), e.Traceparent, e.RecordedAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendAccountability: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryAccountability(ctx context.Context, f evidence.QueryFilter) ([]*evidence.AccountabilityEvidence, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, agent_id, owner_gcid::TEXT,
		decision_id, decision_type,
		decision_provenance::TEXT, evidence_hash,
		lifecycle_stage::TEXT, COALESCE(traceparent,''), recorded_at
		FROM accountability_evidence
		WHERE 1=1`
	fb.applyCommon(f, "agent_id")
	fb.applyTimeAndPage(f, "recorded_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryAccountability",
		func(rows Rows) (*evidence.AccountabilityEvidence, error) {
			var (
				e              evidence.AccountabilityEvidence
				provJSON, life string
				recordedAt     time.Time
			)
			if err := rows.Scan(
				&e.EventID, &e.TenantID, &e.AgentID, &e.OwnerGcid,
				&e.DecisionID, &e.DecisionType,
				&provJSON, &e.EvidenceHash,
				&life, &e.Traceparent, &recordedAt,
			); err != nil {
				return nil, err
			}
			e.Provenance = decodeMap(provJSON)
			e.LifecycleStage = evidence.LifecycleStage(life)
			e.RecordedAt = recordedAt
			return &e, nil
		})
}

// =============================================================================
// D2 — ModelCard
// =============================================================================

func (r *EvidenceRepository) AppendModelCard(ctx context.Context, c *evidence.ModelCard) error {
	if c == nil {
		return errors.New("evidence.AppendModelCard: nil")
	}
	const q = `INSERT INTO model_card_registry (
		event_id, tenant_id, model_id, model_version, card_md,
		training_data_summary, intended_uses, limitations,
		fairness_attestations, lifecycle_stage, registered_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4, $5,
		$6, $7, $8,
		$9::jsonb, $10::imda_lifecycle_stage, $11
	)`
	tenantID := NormalizeTenantForRLS(c.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			c.EventID, tenantID, c.ModelID, c.ModelVersion, c.CardMD,
			c.TrainingDataSummary, c.IntendedUses, c.Limitations,
			jsonbArg(c.FairnessAttestations), string(c.LifecycleStage), c.RegisteredAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendModelCard: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryModelCards(ctx context.Context, f evidence.QueryFilter) ([]*evidence.ModelCard, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, model_id, model_version,
		card_md, training_data_summary, intended_uses, limitations,
		fairness_attestations::TEXT, lifecycle_stage::TEXT, registered_at
		FROM model_card_registry
		WHERE 1=1`
	fb.applyCommon(f, "")
	fb.applyTimeAndPage(f, "registered_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryModelCards",
		func(rows Rows) (*evidence.ModelCard, error) {
			var (
				c              evidence.ModelCard
				fairJSON, life string
				registeredAt   time.Time
			)
			if err := rows.Scan(
				&c.EventID, &c.TenantID, &c.ModelID, &c.ModelVersion,
				&c.CardMD, &c.TrainingDataSummary, &c.IntendedUses, &c.Limitations,
				&fairJSON, &life, &registeredAt,
			); err != nil {
				return nil, err
			}
			c.FairnessAttestations = decodeMap(fairJSON)
			c.LifecycleStage = evidence.LifecycleStage(life)
			c.RegisteredAt = registeredAt
			return &c, nil
		})
}

// =============================================================================
// D2 — DataCard
// =============================================================================

func (r *EvidenceRepository) AppendDataCard(ctx context.Context, d *evidence.DataCard) error {
	if d == nil {
		return errors.New("evidence.AppendDataCard: nil")
	}
	const q = `INSERT INTO data_card_registry (
		event_id, tenant_id, dataset_id, dataset_version, card_md,
		schema_jsonb, provenance, lifecycle_stage, registered_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4, $5,
		$6::jsonb, $7, $8::imda_lifecycle_stage, $9
	)`
	tenantID := NormalizeTenantForRLS(d.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			d.EventID, tenantID, d.DatasetID, d.DatasetVersion, d.CardMD,
			jsonbArg(d.Schema), d.Provenance, string(d.LifecycleStage), d.RegisteredAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendDataCard: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryDataCards(ctx context.Context, f evidence.QueryFilter) ([]*evidence.DataCard, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, dataset_id, dataset_version,
		card_md, schema_jsonb::TEXT, provenance,
		lifecycle_stage::TEXT, registered_at
		FROM data_card_registry
		WHERE 1=1`
	fb.applyCommon(f, "")
	fb.applyTimeAndPage(f, "registered_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryDataCards",
		func(rows Rows) (*evidence.DataCard, error) {
			var (
				d                evidence.DataCard
				schemaJSON, life string
				registeredAt     time.Time
			)
			if err := rows.Scan(
				&d.EventID, &d.TenantID, &d.DatasetID, &d.DatasetVersion,
				&d.CardMD, &schemaJSON, &d.Provenance,
				&life, &registeredAt,
			); err != nil {
				return nil, err
			}
			d.Schema = decodeMap(schemaJSON)
			d.LifecycleStage = evidence.LifecycleStage(life)
			d.RegisteredAt = registeredAt
			return &d, nil
		})
}

// =============================================================================
// D2 — DecisionExplanation
// =============================================================================

func (r *EvidenceRepository) AppendDecisionExplanation(ctx context.Context, e *evidence.DecisionExplanation) error {
	if e == nil {
		return errors.New("evidence.AppendDecisionExplanation: nil")
	}
	const q = `INSERT INTO decision_explanation (
		event_id, tenant_id, decision_id, audience,
		explanation_md, confidence_score, lifecycle_stage, generated_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4::explanation_audience,
		$5, $6, $7::imda_lifecycle_stage, $8
	)`
	tenantID := NormalizeTenantForRLS(e.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			e.EventID, tenantID, e.DecisionID, string(e.Audience),
			e.ExplanationMD, e.ConfidenceScore, string(e.LifecycleStage), e.GeneratedAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendDecisionExplanation: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryDecisionExplanation(ctx context.Context, f evidence.QueryFilter) ([]*evidence.DecisionExplanation, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, decision_id,
		audience::TEXT, explanation_md, confidence_score,
		lifecycle_stage::TEXT, generated_at
		FROM decision_explanation
		WHERE 1=1`
	fb.applyCommon(f, "")
	if f.Audience != "" {
		fb.sql += " AND audience = " + fb.add(string(f.Audience)) + "::explanation_audience"
	}
	fb.applyTimeAndPage(f, "generated_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryDecisionExplanation",
		scanDecisionExplanation)
}

// scanDecisionExplanation scans one decision_explanation row. Shared by
// QueryDecisionExplanation + GetDecisionExplanationByDecisionID (identical
// 8-column projection).
func scanDecisionExplanation(rows Rows) (*evidence.DecisionExplanation, error) {
	var (
		e              evidence.DecisionExplanation
		audience, life string
		generatedAt    time.Time
	)
	if err := rows.Scan(
		&e.EventID, &e.TenantID, &e.DecisionID,
		&audience, &e.ExplanationMD, &e.ConfidenceScore,
		&life, &generatedAt,
	); err != nil {
		return nil, err
	}
	e.Audience = evidence.Audience(audience)
	e.LifecycleStage = evidence.LifecycleStage(life)
	e.GeneratedAt = generatedAt
	return &e, nil
}

// GetDecisionExplanationByDecisionID retrieves explanations for a single
// decision_id, role-filtered by viewer audience. Mirrors the SQL view
// definitions in 0003_imda_evidence.sql lines 550-565.
func (r *EvidenceRepository) GetDecisionExplanationByDecisionID(ctx context.Context, tenantID, decisionID string, viewer evidence.Audience) ([]*evidence.DecisionExplanation, error) {
	q := `SELECT event_id::TEXT, tenant_id::TEXT, decision_id,
		audience::TEXT, explanation_md, confidence_score,
		lifecycle_stage::TEXT, generated_at
		FROM decision_explanation
		WHERE tenant_id = $1::uuid AND decision_id = $2`
	tenantID = NormalizeTenantForRLS(tenantID)
	args := []any{tenantID, decisionID}
	switch viewer {
	case evidence.AudienceLearner:
		q += " AND audience = 'learner'::explanation_audience"
	case evidence.AudienceInstructorAdmin:
		q += " AND audience IN ('instructor_admin'::explanation_audience, 'learner'::explanation_audience)"
	case evidence.AudienceAuditor:
		// no extra filter — auditor sees all
	}
	q += " ORDER BY generated_at DESC"

	return scanRowsTx(ctx, r.q, tenantID, q, args, "evidence.GetDecisionExplanationByDecisionID",
		scanDecisionExplanation)
}

// =============================================================================
// D3 — RedTeamRun
// =============================================================================

func (r *EvidenceRepository) AppendRedTeamRun(ctx context.Context, run *evidence.RedTeamRun) error {
	if run == nil {
		return errors.New("evidence.AppendRedTeamRun: nil")
	}
	const q = `INSERT INTO red_team_runs (
		event_id, tenant_id, run_id, agent_id,
		scenario_jsonb, verdict, findings_jsonb,
		lifecycle_stage, run_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4,
		$5::jsonb, $6, $7::jsonb,
		$8::imda_lifecycle_stage, $9
	)`
	tenantID := NormalizeTenantForRLS(run.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			run.EventID, tenantID, run.RunID, run.AgentID,
			jsonbArg(run.Scenario), run.Verdict, jsonbArg(run.Findings),
			string(run.LifecycleStage), run.RunAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendRedTeamRun: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryRedTeamRuns(ctx context.Context, f evidence.QueryFilter) ([]*evidence.RedTeamRun, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, run_id, agent_id,
		scenario_jsonb::TEXT, verdict, findings_jsonb::TEXT,
		lifecycle_stage::TEXT, run_at
		FROM red_team_runs
		WHERE 1=1`
	fb.applyCommon(f, "agent_id")
	fb.applyTimeAndPage(f, "run_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryRedTeamRuns",
		func(rows Rows) (*evidence.RedTeamRun, error) {
			var (
				run                        evidence.RedTeamRun
				scenarioJSON, findingsJSON string
				life                       string
				runAt                      time.Time
			)
			if err := rows.Scan(
				&run.EventID, &run.TenantID, &run.RunID, &run.AgentID,
				&scenarioJSON, &run.Verdict, &findingsJSON,
				&life, &runAt,
			); err != nil {
				return nil, err
			}
			run.Scenario = decodeMap(scenarioJSON)
			run.Findings = decodeMap(findingsJSON)
			run.LifecycleStage = evidence.LifecycleStage(life)
			run.RunAt = runAt
			return &run, nil
		})
}

// =============================================================================
// D3 — EvalRun
// =============================================================================

func (r *EvidenceRepository) AppendEvalRun(ctx context.Context, run *evidence.EvalRun) error {
	if run == nil {
		return errors.New("evidence.AppendEvalRun: nil")
	}
	const q = `INSERT INTO eval_runs (
		event_id, tenant_id, run_id, agent_id, eval_suite,
		score, baseline_score, regressed, lifecycle_stage, run_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4, $5,
		$6, $7, $8, $9::imda_lifecycle_stage, $10
	)`
	tenantID := NormalizeTenantForRLS(run.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			run.EventID, tenantID, run.RunID, run.AgentID, run.EvalSuite,
			run.Score, run.BaselineScore, run.Regressed,
			string(run.LifecycleStage), run.RunAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendEvalRun: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryEvalRuns(ctx context.Context, f evidence.QueryFilter) ([]*evidence.EvalRun, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, run_id, agent_id, eval_suite,
		score, baseline_score, regressed,
		lifecycle_stage::TEXT, run_at
		FROM eval_runs
		WHERE 1=1`
	fb.applyCommon(f, "agent_id")
	fb.applyTimeAndPage(f, "run_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryEvalRuns",
		func(rows Rows) (*evidence.EvalRun, error) {
			var (
				run   evidence.EvalRun
				life  string
				runAt time.Time
			)
			if err := rows.Scan(
				&run.EventID, &run.TenantID, &run.RunID, &run.AgentID, &run.EvalSuite,
				&run.Score, &run.BaselineScore, &run.Regressed,
				&life, &runAt,
			); err != nil {
				return nil, err
			}
			run.LifecycleStage = evidence.LifecycleStage(life)
			run.RunAt = runAt
			return &run, nil
		})
}

// =============================================================================
// D3 — CostAnomaly
// =============================================================================

func (r *EvidenceRepository) AppendCostAnomaly(ctx context.Context, a *evidence.CostAnomaly) error {
	if a == nil {
		return errors.New("evidence.AppendCostAnomaly: nil")
	}
	const q = `INSERT INTO cost_anomalies (
		event_id, tenant_id, anomaly_id, agent_id,
		baseline_micros, observed_micros, sigma_factor,
		lifecycle_stage, recorded_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4,
		$5, $6, $7,
		$8::imda_lifecycle_stage, $9
	)`
	tenantID := NormalizeTenantForRLS(a.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			a.EventID, tenantID, a.AnomalyID, a.AgentID,
			a.BaselineMicros, a.ObservedMicros, a.SigmaFactor,
			string(a.LifecycleStage), a.RecordedAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendCostAnomaly: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryCostAnomalies(ctx context.Context, f evidence.QueryFilter) ([]*evidence.CostAnomaly, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, anomaly_id, agent_id,
		baseline_micros, observed_micros, sigma_factor,
		lifecycle_stage::TEXT, recorded_at
		FROM cost_anomalies
		WHERE 1=1`
	fb.applyCommon(f, "agent_id")
	fb.applyTimeAndPage(f, "recorded_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryCostAnomalies",
		func(rows Rows) (*evidence.CostAnomaly, error) {
			var (
				a          evidence.CostAnomaly
				life       string
				recordedAt time.Time
			)
			if err := rows.Scan(
				&a.EventID, &a.TenantID, &a.AnomalyID, &a.AgentID,
				&a.BaselineMicros, &a.ObservedMicros, &a.SigmaFactor,
				&life, &recordedAt,
			); err != nil {
				return nil, err
			}
			a.LifecycleStage = evidence.LifecycleStage(life)
			a.RecordedAt = recordedAt
			return &a, nil
		})
}

// =============================================================================
// D3 — CircuitBreaker (state machine, UPSERT)
// =============================================================================

func (r *EvidenceRepository) UpsertCircuitBreaker(ctx context.Context, cb *evidence.CircuitBreaker) error {
	if cb == nil {
		return errors.New("evidence.UpsertCircuitBreaker: nil")
	}
	const q = `INSERT INTO circuit_breaker_state (
		tenant_id, agent_id, state, failure_count,
		lifecycle_stage, last_transitioned_at
	) VALUES (
		$1::uuid, $2, $3::circuit_breaker_state_kind, $4,
		$5::imda_lifecycle_stage, $6
	)
	ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
		state = EXCLUDED.state,
		failure_count = EXCLUDED.failure_count,
		lifecycle_stage = EXCLUDED.lifecycle_stage,
		last_transitioned_at = EXCLUDED.last_transitioned_at`

	tenantID := NormalizeTenantForRLS(cb.TenantID())
	if err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			tenantID, cb.AgentID(), string(cb.State()), cb.FailureCount(),
			string(cb.LifecycleStage()), cb.LastTransitionedAt(),
		)
	}); err != nil {
		return fmt.Errorf("evidence.UpsertCircuitBreaker: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryCircuitBreakers(ctx context.Context, f evidence.QueryFilter) ([]*evidence.CircuitBreaker, error) {
	q := `SELECT tenant_id::TEXT, agent_id, state::TEXT, failure_count,
		lifecycle_stage::TEXT, last_transitioned_at
		FROM circuit_breaker_state
		WHERE 1=1`
	args := []any{}
	idx := 0
	addArg := func(v any) string {
		idx++
		args = append(args, v)
		return fmt.Sprintf("$%d", idx)
	}
	tenantID := NormalizeTenantForRLS(f.TenantID)
	if f.TenantID != "" {
		q += " AND tenant_id = " + addArg(tenantID) + "::uuid"
	}
	if f.AgentID != "" {
		q += " AND agent_id = " + addArg(f.AgentID)
	}
	q += " ORDER BY last_transitioned_at DESC"
	if f.Limit > 0 {
		q += " LIMIT " + addArg(f.Limit)
	}
	if f.Offset > 0 {
		q += " OFFSET " + addArg(f.Offset)
	}

	return scanRowsTx(ctx, r.q, tenantID, q, args, "evidence.QueryCircuitBreakers",
		func(rows Rows) (*evidence.CircuitBreaker, error) {
			var (
				cbTenant, agentID, state, life string
				failureCount                   int
				transitionedAt                 time.Time
			)
			if err := rows.Scan(&cbTenant, &agentID, &state, &failureCount, &life, &transitionedAt); err != nil {
				return nil, err
			}
			cb := evidence.NewCircuitBreaker(cbTenant, agentID)
			// Reconstruct state via TransitionTo; failure_count is reset to 0
			// in fresh constructor — replay failures to match. Reasonable
			// approximation; full audit trail lives in events.
			cb.TransitionTo(evidence.CircuitBreakerState(state))
			for i := 0; i < failureCount; i++ {
				cb.RecordFailure()
			}
			return cb, nil
		})
}

// =============================================================================
// D3 — Quarantine (state machine, UPSERT)
// =============================================================================

func (r *EvidenceRepository) UpsertQuarantine(ctx context.Context, qe *evidence.Quarantine) error {
	if qe == nil {
		return errors.New("evidence.UpsertQuarantine: nil")
	}
	// quarantine_state has no natural unique key in 0003 — the migration
	// allows multiple rows per (tenant, agent). For UpsertQuarantine we
	// INSERT a fresh row each time; releases overwrite via Release()
	// updating released_at on the in-memory domain object before we
	// re-call UpsertQuarantine. Live DB does NOT enforce uniqueness here.
	const q = `INSERT INTO quarantine_state (
		tenant_id, agent_id, reason,
		lifecycle_stage, quarantined_at, released_at
	) VALUES (
		$1::uuid, $2, $3,
		$4::imda_lifecycle_stage, $5, $6
	)`
	var releasedAt any
	if qe.ReleasedAt != nil {
		releasedAt = *qe.ReleasedAt
	} else {
		releasedAt = nil
	}
	tenantID := NormalizeTenantForRLS(qe.TenantID)
	if err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			tenantID, qe.AgentID, qe.Reason,
			string(qe.LifecycleStage), qe.QuarantinedAt, releasedAt,
		)
	}); err != nil {
		return fmt.Errorf("evidence.UpsertQuarantine: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryQuarantines(ctx context.Context, f evidence.QueryFilter) ([]*evidence.Quarantine, error) {
	q := `SELECT tenant_id::TEXT, agent_id, reason,
		lifecycle_stage::TEXT, quarantined_at, released_at
		FROM quarantine_state
		WHERE 1=1`
	args := []any{}
	idx := 0
	addArg := func(v any) string {
		idx++
		args = append(args, v)
		return fmt.Sprintf("$%d", idx)
	}
	tenantID := NormalizeTenantForRLS(f.TenantID)
	if f.TenantID != "" {
		q += " AND tenant_id = " + addArg(tenantID) + "::uuid"
	}
	if f.AgentID != "" {
		q += " AND agent_id = " + addArg(f.AgentID)
	}
	q += " ORDER BY quarantined_at DESC"
	if f.Limit > 0 {
		q += " LIMIT " + addArg(f.Limit)
	}
	if f.Offset > 0 {
		q += " OFFSET " + addArg(f.Offset)
	}

	return scanRowsTx(ctx, r.q, tenantID, q, args, "evidence.QueryQuarantines",
		func(rows Rows) (*evidence.Quarantine, error) {
			var (
				qe            evidence.Quarantine
				life          string
				quarantinedAt time.Time
				releasedAt    *time.Time
			)
			if err := rows.Scan(
				&qe.TenantID, &qe.AgentID, &qe.Reason,
				&life, &quarantinedAt, &releasedAt,
			); err != nil {
				return nil, err
			}
			qe.LifecycleStage = evidence.LifecycleStage(life)
			qe.QuarantinedAt = quarantinedAt
			qe.ReleasedAt = releasedAt
			return &qe, nil
		})
}

// =============================================================================
// D4 — BiasTestRun
// =============================================================================

func (r *EvidenceRepository) AppendBiasTestRun(ctx context.Context, run *evidence.BiasTestRun) error {
	if run == nil {
		return errors.New("evidence.AppendBiasTestRun: nil")
	}
	const q = `INSERT INTO bias_test_runs (
		event_id, tenant_id, run_id, agent_id,
		protected_attribute, test_type, score, threshold, passed,
		lifecycle_stage, run_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4,
		$5, $6, $7, $8, $9,
		$10::imda_lifecycle_stage, $11
	)`
	tenantID := NormalizeTenantForRLS(run.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			run.EventID, tenantID, run.RunID, run.AgentID,
			run.ProtectedAttribute, run.TestType, run.Score, run.Threshold, run.Passed,
			string(run.LifecycleStage), run.RunAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendBiasTestRun: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryBiasTestRuns(ctx context.Context, f evidence.QueryFilter) ([]*evidence.BiasTestRun, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, run_id, agent_id,
		protected_attribute, test_type, score, threshold, passed,
		lifecycle_stage::TEXT, run_at
		FROM bias_test_runs
		WHERE 1=1`
	fb.applyCommon(f, "agent_id")
	fb.applyTimeAndPage(f, "run_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryBiasTestRuns",
		func(rows Rows) (*evidence.BiasTestRun, error) {
			var (
				run   evidence.BiasTestRun
				life  string
				runAt time.Time
			)
			if err := rows.Scan(
				&run.EventID, &run.TenantID, &run.RunID, &run.AgentID,
				&run.ProtectedAttribute, &run.TestType, &run.Score, &run.Threshold, &run.Passed,
				&life, &runAt,
			); err != nil {
				return nil, err
			}
			run.LifecycleStage = evidence.LifecycleStage(life)
			run.RunAt = runAt
			return &run, nil
		})
}

// =============================================================================
// D4 — HITLDecision
// =============================================================================

func (r *EvidenceRepository) AppendHITLDecision(ctx context.Context, d *evidence.HITLDecision) error {
	if d == nil {
		return errors.New("evidence.AppendHITLDecision: nil")
	}
	const q = `INSERT INTO hitl_decision_log (
		event_id, tenant_id, decision_id, run_id, operator_gcid,
		assignee_gcid,
		decision, autonomy_level, edit_payload,
		lifecycle_stage, decided_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4, $5::uuid,
		$6::uuid,
		$7::hitl_decision_verdict, $8::autonomy_level, $9::jsonb,
		$10::imda_lifecycle_stage, $11
	)`
	// AssigneeGcid is NULL-in-NULL-out — pgx pushes nil *string as SQL NULL.
	// operator_gcid is likewise nullable since migration 0010: a PENDING gate
	// (no operator decided yet) carries a blank OperatorGcid, which MUST be
	// pushed as SQL NULL — an empty string would fail the $5::uuid cast. A
	// resolved verdict row carries a real GCID.
	tenantID := NormalizeTenantForRLS(d.TenantID)
	operatorArg := nullableUUIDArg(d.OperatorGcid)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			d.EventID, tenantID, d.DecisionID, d.RunID, operatorArg,
			d.AssigneeGcid,
			string(d.Decision), string(d.AutonomyLevel), jsonbArg(d.EditPayload),
			string(d.LifecycleStage), d.DecidedAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendHITLDecision: %w", err)
	}
	return nil
}

// LoadHITLDecision returns the single hitl_decision_log row identified by
// (tenant_id, decision_id) or ErrNotFound. Tenant-scoped — cross-tenant
// access surfaces as ErrNotFound rather than leaking existence.
//
// Mirrors the 11-column scan shape of QueryHITLDecisions so the row can flow
// through the same domain aggregate without per-call divergence.
func (r *EvidenceRepository) LoadHITLDecision(ctx context.Context, tenantID, decisionID string) (*evidence.HITLDecision, error) {
	const q = `SELECT event_id::TEXT, tenant_id::TEXT, decision_id, run_id, operator_gcid::TEXT,
		assignee_gcid::TEXT,
		decision::TEXT, autonomy_level::TEXT, edit_payload::TEXT,
		lifecycle_stage::TEXT, decided_at
		FROM hitl_decision_log
		WHERE tenant_id = $1::uuid AND decision_id = $2
		ORDER BY decided_at DESC NULLS LAST, event_id DESC
		LIMIT 1`
	tenantID = NormalizeTenantForRLS(tenantID)
	var (
		d                                  evidence.HITLDecision
		operatorNS, assigneeNS             sql.NullString
		decision, autonomy, editJSON, life string
		decidedAt                          time.Time
	)
	if err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.QueryRow(ctx, q, tenantID, decisionID).Scan(
			&d.EventID, &d.TenantID, &d.DecisionID, &d.RunID, &operatorNS,
			&assigneeNS,
			&decision, &autonomy, &editJSON,
			&life, &decidedAt,
		)
	}); err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, evidence.ErrNotFound
		}
		return nil, fmt.Errorf("evidence.LoadHITLDecision: %w", err)
	}
	// operator_gcid is NULL on a PENDING gate (migration 0010) — surface as "".
	if operatorNS.Valid {
		d.OperatorGcid = operatorNS.String
	}
	if assigneeNS.Valid {
		v := assigneeNS.String
		d.AssigneeGcid = &v
	}
	d.Decision = evidence.HitlVerdict(decision)
	d.AutonomyLevel = evidence.AutonomyLevel(autonomy)
	d.EditPayload = decodeMap(editJSON)
	d.Note = hitlNoteFromEditPayload(d.EditPayload)
	d.LifecycleStage = evidence.LifecycleStage(life)
	d.DecidedAt = decidedAt
	return &d, nil
}

// hitlNoteFromEditPayload extracts the operator verdict note persisted under
// evidence.NoteEditPayloadKey in the edit_payload JSONB column. Mirrors the
// domain-side noteFromEditPayload (unexported there) so the pg loader can
// rehydrate HITLDecision.Note without reaching into the domain internals.
func hitlNoteFromEditPayload(m map[string]any) string {
	if m == nil {
		return ""
	}
	if v, ok := m[evidence.NoteEditPayloadKey].(string); ok {
		return v
	}
	return ""
}

// UpdateAssigneeGcid persists a self-claim or release on hitl_decision_log.
// When assigneeGcid is non-nil the column is set to the (trimmed) value;
// nil clears it (release).
//
// Trigger interaction (resolved 2026-05-26 by migration 0009):
//
// Migration 0003's generic `trg_hitl_decision_log_no_update` originally
// rejected EVERY UPDATE via `enforce_evidence_append_only`. Migration 0009
// replaced that trigger with `trg_hitl_decision_log_assignee_only_update`,
// which permits an UPDATE iff `assignee_gcid` is the SOLE column whose
// value changes (NULL-safe IS DISTINCT FROM check across every other
// column). All other evidence-table append-only semantics are preserved.
//
// `now` is reserved for an updated_at column that doesn't exist on
// hitl_decision_log today (migration 0008 didn't add one). Forward-
// compatible signature for any future migration that adds it.
func (r *EvidenceRepository) UpdateAssigneeGcid(ctx context.Context, tenantID, decisionID string, assigneeGcid *string, now time.Time) error {
	const q = `UPDATE hitl_decision_log
		SET assignee_gcid = $3::uuid
		WHERE tenant_id = $1::uuid
		  AND decision_id = $2`
	_ = now // reserved per godoc
	tenantID = NormalizeTenantForRLS(tenantID)
	if err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q, tenantID, decisionID, assigneeGcid)
	}); err != nil {
		return fmt.Errorf("evidence.UpdateAssigneeGcid: %w", err)
	}
	return nil
}

// RecordHITLVerdict APPENDS a fresh hitl_decision_log row carrying the
// operator's approve/reject verdict.
//
// Append (not in-place UPDATE) is mandated by the schema: migration 0009's
// trigger `enforce_hitl_decision_log_assignee_only_update` rejects any UPDATE
// that changes a column other than assignee_gcid — so decision / operator_gcid
// / decided_at CANNOT be set on the pending row in place. The verdict is
// therefore a new immutable ledger entry sharing the (tenant_id, decision_id,
// run_id) of the pending gate, with a fresh event_id (the aggregate's
// EventID, which the handler regenerates for the verdict row). The optional
// note rides in the edit_payload JSONB under NoteEditPayloadKey (no dedicated
// `note` column exists). Re-delivery is idempotent via the event_id unique
// constraint.
func (r *EvidenceRepository) RecordHITLVerdict(ctx context.Context, src *evidence.HITLDecision) error {
	if src == nil {
		return errors.New("evidence.RecordHITLVerdict: nil")
	}
	return r.AppendHITLDecision(ctx, src)
}

func (r *EvidenceRepository) QueryHITLDecisions(ctx context.Context, f evidence.QueryFilter) ([]*evidence.HITLDecision, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, decision_id, run_id, operator_gcid::TEXT,
		assignee_gcid::TEXT,
		decision::TEXT, autonomy_level::TEXT, edit_payload::TEXT,
		lifecycle_stage::TEXT, decided_at
		FROM hitl_decision_log
		WHERE 1=1`
	fb.applyCommon(f, "")
	fb.applyTimeAndPage(f, "decided_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryHITLDecisions",
		func(rows Rows) (*evidence.HITLDecision, error) {
			var (
				d                                  evidence.HITLDecision
				operatorNS, assigneeNS             sql.NullString
				decision, autonomy, editJSON, life string
				decidedAt                          time.Time
			)
			if err := rows.Scan(
				&d.EventID, &d.TenantID, &d.DecisionID, &d.RunID, &operatorNS,
				&assigneeNS,
				&decision, &autonomy, &editJSON,
				&life, &decidedAt,
			); err != nil {
				return nil, err
			}
			// operator_gcid is NULL on a PENDING gate (migration 0010).
			if operatorNS.Valid {
				d.OperatorGcid = operatorNS.String
			}
			if assigneeNS.Valid {
				v := assigneeNS.String
				d.AssigneeGcid = &v
			}
			d.Decision = evidence.HitlVerdict(decision)
			d.AutonomyLevel = evidence.AutonomyLevel(autonomy)
			d.EditPayload = decodeMap(editJSON)
			d.Note = hitlNoteFromEditPayload(d.EditPayload)
			d.LifecycleStage = evidence.LifecycleStage(life)
			d.DecidedAt = decidedAt
			return &d, nil
		})
}

// =============================================================================
// PolicyViolation (Tier 3 D9 ContentPolicyViolationLog)
// =============================================================================

func (r *EvidenceRepository) AppendPolicyViolation(ctx context.Context, v *evidence.PolicyViolation) error {
	if v == nil {
		return errors.New("evidence.AppendPolicyViolation: nil")
	}
	const q = `INSERT INTO policy_violation_log (
		event_id, tenant_id, agent_id, policy_name, severity, detector,
		detected_payload, lifecycle_stage, detected_at
	) VALUES (
		$1::uuid, $2::uuid, $3, $4, $5, $6,
		$7::jsonb, $8::imda_lifecycle_stage, $9
	)`
	tenantID := NormalizeTenantForRLS(v.TenantID)
	err := r.q.WithTenantTx(ctx, tenantID, func(ctx context.Context, tx TenantScopedQuerier) error {
		return tx.Exec(ctx, q,
			v.EventID, tenantID, v.AgentID, v.PolicyName, v.Severity, v.Detector,
			jsonbArg(v.Payload), string(v.LifecycleStage), v.DetectedAt,
		)
	})
	if err != nil {
		if isAppendOnlyDuplicate(err) {
			return nil
		}
		return fmt.Errorf("evidence.AppendPolicyViolation: %w", err)
	}
	return nil
}

func (r *EvidenceRepository) QueryPolicyViolations(ctx context.Context, f evidence.QueryFilter) ([]*evidence.PolicyViolation, error) {
	f = rlsScopeFilter(f)
	fb := newFilter()
	fb.sql = `SELECT event_id::TEXT, tenant_id::TEXT, agent_id, policy_name, severity, detector,
		detected_payload::TEXT, lifecycle_stage::TEXT, detected_at
		FROM policy_violation_log
		WHERE 1=1`
	fb.applyCommon(f, "agent_id")
	fb.applyTimeAndPage(f, "detected_at")

	return scanRowsTx(ctx, r.q, tenantForFilter(f), fb.sql, fb.args, "evidence.QueryPolicyViolations",
		func(rows Rows) (*evidence.PolicyViolation, error) {
			var (
				v                 evidence.PolicyViolation
				payloadJSON, life string
				detectedAt        time.Time
			)
			if err := rows.Scan(
				&v.EventID, &v.TenantID, &v.AgentID, &v.PolicyName, &v.Severity, &v.Detector,
				&payloadJSON, &life, &detectedAt,
			); err != nil {
				return nil, err
			}
			v.Payload = decodeMap(payloadJSON)
			v.LifecycleStage = evidence.LifecycleStage(life)
			v.DetectedAt = detectedAt
			return &v, nil
		})
}

// =============================================================================
// Helpers
// =============================================================================

// decodeMap parses a JSONB string into map[string]any. Empty/invalid returns
// an empty map (Pub/Sub-safe; never panics on bad input).
func decodeMap(s string) map[string]any {
	if s == "" {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return map[string]any{}
	}
	return out
}

// Compile-time interface check.
var _ evidence.Repository = (*EvidenceRepository)(nil)
