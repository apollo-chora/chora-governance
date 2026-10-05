// evidence_repository_test.go — pgx adapter tests for evidence.Repository
// using the canonical stub Querier pattern from audit_repository_test.go.
//
// Covers all 12 IMDA D1-D4 aggregates:
//
//	D1 — AccountabilityEvidence
//	D2 — ModelCard / DataCard / DecisionExplanation
//	D3 — RedTeamRun / EvalRun / CostAnomaly / CircuitBreaker / Quarantine
//	D4 — BiasTestRun / HITLDecision
//	+  — PolicyViolation (Tier 3 D9 ContentPolicyViolationLog)
package pg_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func newAccountability(t *testing.T) *evidence.AccountabilityEvidence {
	t.Helper()
	a, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID:      uuid.NewString(),
		TenantID:     uuid.NewString(),
		AgentID:      "agent-1",
		OwnerGcid:    uuid.NewString(),
		DecisionID:   "dec-1",
		DecisionType: "policy.gatekeeper",
		Provenance:   map[string]any{"source": "test"},
	})
	if err != nil {
		t.Fatalf("NewAccountabilityEvidence: %v", err)
	}
	return a
}

func newModelCard(t *testing.T) *evidence.ModelCard {
	t.Helper()
	c, err := evidence.NewModelCard(evidence.ModelCardParams{
		EventID:      uuid.NewString(),
		TenantID:     uuid.NewString(),
		ModelID:      "m1",
		ModelVersion: "v1",
		CardMD:       "# Card",
	})
	if err != nil {
		t.Fatalf("NewModelCard: %v", err)
	}
	return c
}

func newDataCard(t *testing.T) *evidence.DataCard {
	t.Helper()
	d, err := evidence.NewDataCard(evidence.DataCardParams{
		EventID:        uuid.NewString(),
		TenantID:       uuid.NewString(),
		DatasetID:      "ds1",
		DatasetVersion: "v1",
		CardMD:         "# Card",
		Schema:         map[string]any{"x": "int"},
	})
	if err != nil {
		t.Fatalf("NewDataCard: %v", err)
	}
	return d
}

func newDecisionExplanation(t *testing.T) *evidence.DecisionExplanation {
	t.Helper()
	e, err := evidence.NewDecisionExplanation(evidence.DecisionExplanationParams{
		EventID:         uuid.NewString(),
		TenantID:        uuid.NewString(),
		DecisionID:      "d1",
		Audience:        evidence.AudienceLearner,
		ExplanationMD:   "## Explanation",
		ConfidenceScore: 0.9,
	})
	if err != nil {
		t.Fatalf("NewDecisionExplanation: %v", err)
	}
	return e
}

func newRedTeamRun(t *testing.T) *evidence.RedTeamRun {
	t.Helper()
	r, err := evidence.NewRedTeamRun(evidence.RedTeamRunParams{
		EventID:  uuid.NewString(),
		TenantID: uuid.NewString(),
		RunID:    "r1",
		AgentID:  "a1",
		Verdict:  "passed",
	})
	if err != nil {
		t.Fatalf("NewRedTeamRun: %v", err)
	}
	return r
}

func newEvalRun(t *testing.T) *evidence.EvalRun {
	t.Helper()
	r, err := evidence.NewEvalRun(evidence.EvalRunParams{
		EventID:       uuid.NewString(),
		TenantID:      uuid.NewString(),
		RunID:         "r1",
		AgentID:       "a1",
		EvalSuite:     "deepeval",
		Score:         0.92,
		BaselineScore: 0.90,
	})
	if err != nil {
		t.Fatalf("NewEvalRun: %v", err)
	}
	return r
}

func newCostAnomaly(t *testing.T) *evidence.CostAnomaly {
	t.Helper()
	a, err := evidence.NewCostAnomaly(evidence.CostAnomalyParams{
		EventID:        uuid.NewString(),
		TenantID:       uuid.NewString(),
		AnomalyID:      "an1",
		AgentID:        "a1",
		BaselineMicros: 1000,
		ObservedMicros: 5000,
		SigmaFactor:    3.5,
	})
	if err != nil {
		t.Fatalf("NewCostAnomaly: %v", err)
	}
	return a
}

func newBiasTestRun(t *testing.T) *evidence.BiasTestRun {
	t.Helper()
	r, err := evidence.NewBiasTestRun(evidence.BiasTestRunParams{
		EventID:            uuid.NewString(),
		TenantID:           uuid.NewString(),
		RunID:              "r1",
		AgentID:            "a1",
		ProtectedAttribute: "gender",
		TestType:           "demographic_parity",
		Score:              0.91,
		Threshold:          0.80,
	})
	if err != nil {
		t.Fatalf("NewBiasTestRun: %v", err)
	}
	return r
}

func newHITLDecision(t *testing.T) *evidence.HITLDecision {
	t.Helper()
	d, err := evidence.NewHITLDecision(evidence.HITLDecisionParams{
		EventID:       uuid.NewString(),
		TenantID:      uuid.NewString(),
		DecisionID:    "d1",
		RunID:         "r1",
		OperatorGcid:  uuid.NewString(),
		Decision:      evidence.HitlApprove,
		AutonomyLevel: evidence.AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewHITLDecision: %v", err)
	}
	return d
}

func newPolicyViolation(t *testing.T) *evidence.PolicyViolation {
	t.Helper()
	v, err := evidence.NewPolicyViolation(evidence.PolicyViolationParams{
		EventID:    uuid.NewString(),
		TenantID:   uuid.NewString(),
		AgentID:    "a1",
		PolicyName: "pii.dlp",
		Severity:   "high",
		Detector:   "dlp",
	})
	if err != nil {
		t.Fatalf("NewPolicyViolation: %v", err)
	}
	return v
}

// -----------------------------------------------------------------------------
// D1 Accountability
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendAccountability_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendAccountability(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendAccountability_EmitsInsert(t *testing.T) {
	t.Parallel()
	a := newAccountability(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendAccountability(context.Background(), a); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO accountability_evidence") {
		t.Errorf("expected INSERT INTO accountability_evidence; got %q", q.execSQL)
	}
}

// TestEvidenceRepository_AppendAccountability_TenantScoped proves the D1
// append path runs inside WithTenantTx so the `SET LOCAL chora.tenant_id`
// GUC is applied BEFORE the INSERT — without it the RLS tenant_isolation
// policy (migration 0003 line 492) rejects the row ("new row violates
// row-level security policy for table accountability_evidence"), which is the
// LIVE defect that kept accountability_evidence at 0 rows + dead-lettered
// every IMDA decision. The GUC value MUST equal the row's own tenant_id so
// the row passes its own policy.
func TestEvidenceRepository_AppendAccountability_TenantScoped(t *testing.T) {
	t.Parallel()
	tenant := uuid.NewString()
	a, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID:      uuid.NewString(),
		TenantID:     tenant,
		AgentID:      "qgen_crew",
		OwnerGcid:    uuid.NewString(),
		DecisionID:   "dec-1",
		DecisionType: "qgen.quality_gate.approved",
		Provenance:   map[string]any{"source": "test"},
	})
	if err != nil {
		t.Fatalf("NewAccountabilityEvidence: %v", err)
	}
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendAccountability(context.Background(), a); err != nil {
		t.Fatalf("AppendAccountability: %v", err)
	}
	if !q.txCalled {
		t.Fatal("expected AppendAccountability to run inside WithTenantTx (RLS GUC); it did not")
	}
	if q.txTenantID != tenant {
		t.Errorf("SET LOCAL chora.tenant_id = %q; want row tenant %q", q.txTenantID, tenant)
	}
	if !contains(q.execSQL, "INSERT INTO accountability_evidence") {
		t.Errorf("expected INSERT INTO accountability_evidence; got %q", q.execSQL)
	}
	// The inserted tenant_id column ($2) must match the GUC so the row
	// satisfies its own tenant_isolation policy.
	if len(q.execArgs) < 2 {
		t.Fatalf("expected >= 2 args; got %d", len(q.execArgs))
	}
	if q.execArgs[1] != tenant {
		t.Errorf("inserted tenant_id arg = %v; want %q", q.execArgs[1], tenant)
	}
}

// TestEvidenceRepository_AppendAccountability_PlatformNormalised proves the
// "platform" envelope sentinel is normalised to the nil UUID for BOTH the
// SET LOCAL chora.tenant_id GUC AND the inserted tenant_id column — the UUID
// column + `::uuid` RLS cast cannot accept 'platform'::uuid.
func TestEvidenceRepository_AppendAccountability_PlatformNormalised(t *testing.T) {
	t.Parallel()
	a, err := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID:      uuid.NewString(),
		TenantID:     "platform",
		AgentID:      "qgen_crew",
		OwnerGcid:    uuid.NewString(),
		DecisionID:   "dec-1",
		DecisionType: "qgen.quality_gate.approved",
	})
	if err != nil {
		t.Fatalf("NewAccountabilityEvidence: %v", err)
	}
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendAccountability(context.Background(), a); err != nil {
		t.Fatalf("AppendAccountability: %v", err)
	}
	if !q.txCalled {
		t.Fatal("expected AppendAccountability to run inside WithTenantTx")
	}
	if q.txTenantID != pg.NilTenantUUID {
		t.Errorf("SET LOCAL chora.tenant_id = %q; want NilTenantUUID %q", q.txTenantID, pg.NilTenantUUID)
	}
	if len(q.execArgs) < 2 {
		t.Fatalf("expected >= 2 args; got %d", len(q.execArgs))
	}
	if q.execArgs[1] != pg.NilTenantUUID {
		t.Errorf("inserted tenant_id arg = %v; want NilTenantUUID %q", q.execArgs[1], pg.NilTenantUUID)
	}
}

// TestEvidenceRepository_QueryAccountability_TenantScoped proves reads are
// RLS-scoped too — without the GUC the policy filters every row to zero
// regardless of the WHERE clause, so the O+ dashboard reads empty.
func TestEvidenceRepository_QueryAccountability_TenantScoped(t *testing.T) {
	t.Parallel()
	tenant := uuid.NewString()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	if _, err := repo.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: tenant}); err != nil {
		t.Fatalf("QueryAccountability: %v", err)
	}
	if !q.txCalled {
		t.Fatal("expected QueryAccountability to run inside WithTenantTx (RLS GUC); it did not")
	}
	if q.txTenantID != tenant {
		t.Errorf("SET LOCAL chora.tenant_id = %q; want filter tenant %q", q.txTenantID, tenant)
	}
}

func TestEvidenceRepository_AppendAccountability_DuplicateIdempotent(t *testing.T) {
	t.Parallel()
	a := newAccountability(t)
	q := &stubQuerier{
		execErr: errors.New("ERROR: duplicate key value violates unique constraint (SQLSTATE 23505)"),
	}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendAccountability(context.Background(), a); err != nil {
		t.Errorf("duplicate should be idempotent; got %v", err)
	}
}

func TestEvidenceRepository_AppendAccountability_OtherErrorWraps(t *testing.T) {
	t.Parallel()
	a := newAccountability(t)
	q := &stubQuerier{execErr: errors.New("db down")}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendAccountability(context.Background(), a); err == nil {
		t.Fatal("expected error to surface")
	}
}

func TestEvidenceRepository_QueryAccountability_EmptyReturnsEmpty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryAccountability(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryAccountability_AppendsFilters(t *testing.T) {
	t.Parallel()
	from := time.Now().Add(-1 * time.Hour)
	to := time.Now()
	var capturedSQL string
	q := &stubQuerier{
		queryFn: func(sql string, _ ...any) (pg.Rows, error) {
			capturedSQL = sql
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryAccountability(context.Background(), evidence.QueryFilter{
		TenantID:       "tenant-1",
		LifecycleStage: evidence.LifecycleRuntime,
		AgentID:        "agent-1",
		From:           &from,
		To:             &to,
		Limit:          50,
		Offset:         10,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, frag := range []string{
		"tenant_id =",
		"lifecycle_stage =",
		"agent_id =",
		"recorded_at >=",
		"recorded_at <=",
		"LIMIT",
		"OFFSET",
	} {
		if !contains(capturedSQL, frag) {
			t.Errorf("expected SQL to contain %q; got: %s", frag, capturedSQL)
		}
	}
}

func TestEvidenceRepository_QueryAccountability_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryAccountability(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D2 ModelCard
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendModelCard_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendModelCard(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendModelCard_EmitsInsert(t *testing.T) {
	t.Parallel()
	c := newModelCard(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendModelCard(context.Background(), c); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO model_card_registry") {
		t.Errorf("expected INSERT INTO model_card_registry; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_AppendModelCard_DuplicateIdempotent(t *testing.T) {
	t.Parallel()
	c := newModelCard(t)
	q := &stubQuerier{
		execErr: errors.New("ERROR: duplicate key (SQLSTATE 23505)"),
	}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendModelCard(context.Background(), c); err != nil {
		t.Errorf("duplicate should be idempotent; got %v", err)
	}
}

func TestEvidenceRepository_QueryModelCards_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryModelCards(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryModelCards_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryModelCards(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D2 DataCard
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendDataCard_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendDataCard(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendDataCard_EmitsInsert(t *testing.T) {
	t.Parallel()
	d := newDataCard(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendDataCard(context.Background(), d); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO data_card_registry") {
		t.Errorf("expected INSERT INTO data_card_registry; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryDataCards_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryDataCards(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryDataCards_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryDataCards(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D2 DecisionExplanation
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendDecisionExplanation_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendDecisionExplanation(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendDecisionExplanation_EmitsInsert(t *testing.T) {
	t.Parallel()
	e := newDecisionExplanation(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendDecisionExplanation(context.Background(), e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO decision_explanation") {
		t.Errorf("expected INSERT INTO decision_explanation; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryDecisionExplanation_FilterByAudience(t *testing.T) {
	t.Parallel()
	var capturedSQL string
	q := &stubQuerier{
		queryFn: func(sql string, _ ...any) (pg.Rows, error) {
			capturedSQL = sql
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryDecisionExplanation(context.Background(), evidence.QueryFilter{
		Audience: evidence.AudienceLearner,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !contains(capturedSQL, "audience =") {
		t.Errorf("expected audience filter; got %q", capturedSQL)
	}
}

func TestEvidenceRepository_QueryDecisionExplanation_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryDecisionExplanation(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEvidenceRepository_GetDecisionExplanationByDecisionID(t *testing.T) {
	t.Parallel()
	var capturedSQL string
	q := &stubQuerier{
		queryFn: func(sql string, _ ...any) (pg.Rows, error) {
			capturedSQL = sql
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.GetDecisionExplanationByDecisionID(context.Background(),
		"tenant-1", "decision-1", evidence.AudienceAuditor)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !contains(capturedSQL, "decision_id =") {
		t.Errorf("expected decision_id filter; got %q", capturedSQL)
	}
}

// -----------------------------------------------------------------------------
// D3 RedTeamRun
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendRedTeamRun_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendRedTeamRun(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendRedTeamRun_EmitsInsert(t *testing.T) {
	t.Parallel()
	r := newRedTeamRun(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendRedTeamRun(context.Background(), r); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO red_team_runs") {
		t.Errorf("expected INSERT INTO red_team_runs; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryRedTeamRuns_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryRedTeamRuns(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryRedTeamRuns_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryRedTeamRuns(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D3 EvalRun
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendEvalRun_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendEvalRun(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendEvalRun_EmitsInsert(t *testing.T) {
	t.Parallel()
	r := newEvalRun(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendEvalRun(context.Background(), r); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO eval_runs") {
		t.Errorf("expected INSERT INTO eval_runs; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryEvalRuns_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryEvalRuns(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryEvalRuns_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryEvalRuns(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D3 CostAnomaly
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendCostAnomaly_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendCostAnomaly(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendCostAnomaly_EmitsInsert(t *testing.T) {
	t.Parallel()
	a := newCostAnomaly(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendCostAnomaly(context.Background(), a); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO cost_anomalies") {
		t.Errorf("expected INSERT INTO cost_anomalies; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryCostAnomalies_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryCostAnomalies(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryCostAnomalies_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryCostAnomalies(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D3 CircuitBreaker (state machine — UPSERT)
// -----------------------------------------------------------------------------

func TestEvidenceRepository_UpsertCircuitBreaker_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.UpsertCircuitBreaker(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_UpsertCircuitBreaker_EmitsUpsert(t *testing.T) {
	t.Parallel()
	cb := evidence.NewCircuitBreaker(uuid.NewString(), "agent-1")
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.UpsertCircuitBreaker(context.Background(), cb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO circuit_breaker_state") {
		t.Errorf("expected INSERT INTO circuit_breaker_state; got %q", q.execSQL)
	}
	if !contains(q.execSQL, "ON CONFLICT") {
		t.Errorf("expected ON CONFLICT upsert; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryCircuitBreakers_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryCircuitBreakers(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryCircuitBreakers_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryCircuitBreakers(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D3 Quarantine (state machine — UPSERT)
// -----------------------------------------------------------------------------

func TestEvidenceRepository_UpsertQuarantine_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.UpsertQuarantine(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_UpsertQuarantine_EmitsInsert(t *testing.T) {
	t.Parallel()
	qe := evidence.NewQuarantine(uuid.NewString(), "agent-1", "reason")
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.UpsertQuarantine(context.Background(), qe); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO quarantine_state") {
		t.Errorf("expected INSERT INTO quarantine_state; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryQuarantines_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryQuarantines(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryQuarantines_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryQuarantines(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D4 BiasTestRun
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendBiasTestRun_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendBiasTestRun(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendBiasTestRun_EmitsInsert(t *testing.T) {
	t.Parallel()
	r := newBiasTestRun(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendBiasTestRun(context.Background(), r); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO bias_test_runs") {
		t.Errorf("expected INSERT INTO bias_test_runs; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryBiasTestRuns_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryBiasTestRuns(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryBiasTestRuns_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryBiasTestRuns(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// D4 HITLDecision
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendHITLDecision_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendHITLDecision(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendHITLDecision_EmitsInsert(t *testing.T) {
	t.Parallel()
	d := newHITLDecision(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO hitl_decision_log") {
		t.Errorf("expected INSERT INTO hitl_decision_log; got %q", q.execSQL)
	}
}

// newPendingHITLDecision builds a PENDING gate row (no operator, "pending"
// verdict) for the repo-level append tests.
func newPendingHITLDecisionPG(t *testing.T) *evidence.HITLDecision {
	t.Helper()
	d, err := evidence.NewPendingHITLDecision(evidence.PendingHITLDecisionParams{
		EventID:       uuid.NewString(),
		TenantID:      uuid.NewString(),
		DecisionID:    "dec-pending-1",
		RunID:         "run-1",
		AutonomyLevel: evidence.AutonomyHitlL0,
		Summary:       "quality warning at max retries",
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	return d
}

// TestEvidenceRepository_AppendPendingHITL_EmitsInsertInsideTenantTx asserts a
// PENDING gate appends via the same INSERT-inside-WithTenantTx path as a
// resolved row (C1 RLS-scoping) — the pending verdict must not bypass the GUC.
func TestEvidenceRepository_AppendPendingHITL_EmitsInsertInsideTenantTx(t *testing.T) {
	t.Parallel()
	d := newPendingHITLDecisionPG(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("AppendHITLDecision (pending): %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO hitl_decision_log") {
		t.Errorf("expected INSERT INTO hitl_decision_log; got %q", q.execSQL)
	}
	if !q.txCalled {
		t.Fatal("expected pending AppendHITLDecision to run inside WithTenantTx (RLS GUC); it did not")
	}
}

// TestEvidenceRepository_AppendPendingHITL_OperatorGcidNull asserts the blank
// operator_gcid on a pending gate is pushed as SQL NULL (not an empty string,
// which would fail the operator_gcid::uuid cast). The operator_gcid arg is
// position 5 in the INSERT.
func TestEvidenceRepository_AppendPendingHITL_OperatorGcidNull(t *testing.T) {
	t.Parallel()
	d := newPendingHITLDecisionPG(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("AppendHITLDecision (pending): %v", err)
	}
	if len(q.execArgs) < 5 {
		t.Fatalf("expected >=5 INSERT args; got %d", len(q.execArgs))
	}
	// Arg index 4 (1-based $5) is operator_gcid. For a pending gate it MUST be
	// SQL NULL. pgx encodes a typed-nil *string as NULL, so the canonical
	// representation here is a (*string)(nil) — NOT an empty string.
	op := q.execArgs[4]
	switch v := op.(type) {
	case nil:
		// untyped nil — also NULL; acceptable.
	case *string:
		if v != nil {
			t.Errorf("operator_gcid arg = %q; want nil *string (SQL NULL) for a pending gate", *v)
		}
	case string:
		t.Errorf("operator_gcid arg is a string %q; want nil *string (SQL NULL) for a pending gate", v)
	default:
		t.Errorf("operator_gcid arg = %#v; want nil *string (SQL NULL) for a pending gate", op)
	}
}

// TestEvidenceRepository_AppendResolvedHITL_OperatorGcidNonNull guards that a
// RESOLVED verdict row still binds the real operator_gcid (NOT NULL) — the
// nullable-operator change must only NULL a BLANK gcid.
func TestEvidenceRepository_AppendResolvedHITL_OperatorGcidNonNull(t *testing.T) {
	t.Parallel()
	d := newHITLDecision(t) // resolved approve with a real operator UUID
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendHITLDecision(context.Background(), d); err != nil {
		t.Fatalf("AppendHITLDecision (resolved): %v", err)
	}
	op := q.execArgs[4]
	v, ok := op.(*string)
	if !ok || v == nil || *v == "" {
		t.Errorf("resolved operator_gcid arg = %#v; want a non-nil *string with the operator UUID", op)
	}
}

func TestEvidenceRepository_RecordHITLVerdict_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.RecordHITLVerdict(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

// RecordHITLVerdict must APPEND (INSERT) — the verdict columns are append-only
// at the DB layer (migration 0009 trigger), so it MUST NOT emit an UPDATE.
func TestEvidenceRepository_RecordHITLVerdict_EmitsInsertNotUpdate(t *testing.T) {
	t.Parallel()
	d := newHITLDecision(t)
	if err := d.Approve(uuid.NewString(), "verdict note", time.Now().UTC()); err != nil {
		// d already carries an approve verdict from the helper; Approve on a
		// terminal row returns ErrHITLTerminal — reset to pending first.
		d.Decision = evidence.HitlVerdict("pending")
		d.OperatorGcid = ""
		if err := d.Approve(uuid.NewString(), "verdict note", time.Now().UTC()); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.RecordHITLVerdict(context.Background(), d); err != nil {
		t.Fatalf("RecordHITLVerdict: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO hitl_decision_log") {
		t.Errorf("expected INSERT (append-only verdict); got %q", q.execSQL)
	}
	if contains(q.execSQL, "UPDATE hitl_decision_log") {
		t.Errorf("verdict MUST be appended, not UPDATEd in place; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryHITLDecisions_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryHITLDecisions_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// PolicyViolation
// -----------------------------------------------------------------------------

func TestEvidenceRepository_AppendPolicyViolation_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	if err := repo.AppendPolicyViolation(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil")
	}
}

func TestEvidenceRepository_AppendPolicyViolation_EmitsInsert(t *testing.T) {
	t.Parallel()
	v := newPolicyViolation(t)
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendPolicyViolation(context.Background(), v); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO policy_violation_log") {
		t.Errorf("expected INSERT INTO policy_violation_log; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_QueryPolicyViolations_Empty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryPolicyViolations(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestEvidenceRepository_QueryPolicyViolations_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryPolicyViolations(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// -----------------------------------------------------------------------------
// Scan path coverage — exercises Rows.Scan + struct hydration
// -----------------------------------------------------------------------------

func TestEvidenceRepository_QueryAccountability_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "agent-1", "owner-1",
					"dec-1", "type-1",
					`{"k":"v"}`, "hash-1",
					"runtime", "trace-1", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryAccountability(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row; got %d", len(out))
	}
	if out[0].EventID != "event-1" {
		t.Errorf("EventID = %q", out[0].EventID)
	}
	if out[0].LifecycleStage != evidence.LifecycleRuntime {
		t.Errorf("LifecycleStage = %q", out[0].LifecycleStage)
	}
	if out[0].Provenance["k"] != "v" {
		t.Errorf("Provenance = %+v", out[0].Provenance)
	}
}

func TestEvidenceRepository_QueryAccountability_ScanError(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{{"x"}}, scanErr: errors.New("scan")}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryAccountability(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected scan error")
	}
}

func TestEvidenceRepository_QueryAccountability_IterError(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{iterErr: errors.New("iter")}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.QueryAccountability(context.Background(), evidence.QueryFilter{})
	if err == nil {
		t.Fatal("expected iter error")
	}
}

func TestEvidenceRepository_QueryModelCards_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "m1", "v1",
					"# Card", "summary", "uses", "limits",
					`{"fair":1}`, "runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryModelCards(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].ModelID != "m1" {
		t.Errorf("got %+v", out)
	}
}

func TestEvidenceRepository_QueryDataCards_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "ds1", "v1",
					"# Card", `{}`, "prov",
					"runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryDataCards(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].DatasetID != "ds1" {
		t.Errorf("got %+v", out)
	}
}

func TestEvidenceRepository_QueryDecisionExplanation_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "dec-1",
					"learner", "## Explanation", 0.9,
					"runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryDecisionExplanation(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].Audience != evidence.AudienceLearner {
		t.Errorf("got %+v", out)
	}
}

func TestEvidenceRepository_GetDecisionExplanationByDecisionID_AuditorSeesAll(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	var capturedSQL string
	q := &stubQuerier{
		queryFn: func(sql string, _ ...any) (pg.Rows, error) {
			capturedSQL = sql
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "dec-1",
					"auditor", "## All", 1.0,
					"runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.GetDecisionExplanationByDecisionID(context.Background(),
		"tenant-1", "dec-1", evidence.AudienceAuditor)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("expected 1 row; got %d", len(out))
	}
	// Auditor view has no extra audience filter; verify.
	if contains(capturedSQL, "audience IN") {
		t.Errorf("auditor view should not filter by audience IN; got: %s", capturedSQL)
	}
}

func TestEvidenceRepository_GetDecisionExplanationByDecisionID_InstructorSeesLearnerPlusSelf(t *testing.T) {
	t.Parallel()
	var capturedSQL string
	q := &stubQuerier{
		queryFn: func(sql string, _ ...any) (pg.Rows, error) {
			capturedSQL = sql
			return &stubRows{}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, _ = repo.GetDecisionExplanationByDecisionID(context.Background(),
		"tenant-1", "dec-1", evidence.AudienceInstructorAdmin)
	if !contains(capturedSQL, "audience IN") {
		t.Errorf("instructor view should filter by audience IN; got: %s", capturedSQL)
	}
}

func TestEvidenceRepository_QueryRedTeamRuns_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "r1", "a1",
					`{}`, "passed", `{}`,
					"pre_deploy", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryRedTeamRuns(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].Verdict != "passed" {
		t.Errorf("got %+v", out)
	}
}

func TestEvidenceRepository_QueryEvalRuns_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "r1", "a1", "deepeval",
					0.92, 0.90, false,
					"pre_deploy", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryEvalRuns(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].EvalSuite != "deepeval" {
		t.Errorf("got %+v", out)
	}
}

func TestEvidenceRepository_QueryCostAnomalies_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "an1", "a1",
					int64(1000), int64(5000), 3.5,
					"runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryCostAnomalies(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].AnomalyID != "an1" {
		t.Errorf("got %+v", out)
	}
}

func TestEvidenceRepository_QueryCircuitBreakers_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"tenant-1", "agent-1", "open", 3,
					"runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryCircuitBreakers(context.Background(), evidence.QueryFilter{
		TenantID: "tenant-1",
		AgentID:  "agent-1",
		Limit:    10,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row; got %d", len(out))
	}
	if out[0].State() != evidence.CircuitOpen {
		t.Errorf("State = %q; want open", out[0].State())
	}
	if out[0].FailureCount() != 3 {
		t.Errorf("FailureCount = %d; want 3", out[0].FailureCount())
	}
}

func TestEvidenceRepository_QueryQuarantines_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"tenant-1", "agent-1", "PII leak",
					"runtime", now, (*time.Time)(nil),
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryQuarantines(context.Background(), evidence.QueryFilter{
		TenantID: "tenant-1",
		AgentID:  "agent-1",
		Limit:    10,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row; got %d", len(out))
	}
	if !out[0].IsActive() {
		t.Errorf("expected active quarantine (ReleasedAt nil)")
	}
}

func TestEvidenceRepository_QueryBiasTestRuns_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "r1", "a1",
					"gender", "demographic_parity", 0.91, 0.80, true,
					"pre_deploy", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryBiasTestRuns(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || !out[0].Passed {
		t.Errorf("got %+v", out)
	}
}

func TestEvidenceRepository_QueryHITLDecisions_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	// 11 columns per the migration-0008 expanded shape:
	//   event_id, tenant_id, decision_id, run_id, operator_gcid,
	//   assignee_gcid (NULL),
	//   decision, autonomy_level, edit_payload,
	//   lifecycle_stage, decided_at
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "dec-1", "run-1", "op-1",
					nil, // assignee_gcid NULL — unassigned default
					"approve", "hitl_l1", `{}`,
					"runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].Decision != evidence.HitlApprove {
		t.Errorf("got %+v", out)
	}
	if out[0].AssigneeGcid != nil {
		t.Errorf("AssigneeGcid = %v; want nil (NULL)", out[0].AssigneeGcid)
	}
}

func TestEvidenceRepository_QueryHITLDecisions_ScansAssigneeWhenPresent(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "dec-1", "run-1", "op-1",
					"alice-gcid", // assignee_gcid present
					"approve", "hitl_l1", `{}`,
					"runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].AssigneeGcid == nil || *out[0].AssigneeGcid != "alice-gcid" {
		t.Errorf("AssigneeGcid = %v; want alice-gcid", out[0].AssigneeGcid)
	}
}

// -----------------------------------------------------------------------------
// HITLDecision — LoadHITLDecision (N7)
// -----------------------------------------------------------------------------

func TestEvidenceRepository_LoadHITLDecision_NotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: pg.ErrNoRows}
		},
	}
	repo := pg.NewEvidenceRepository(q)
	_, err := repo.LoadHITLDecision(context.Background(), "tenant-1", "missing")
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Errorf("err = %v; want ErrNotFound", err)
	}
}

func TestEvidenceRepository_LoadHITLDecision_HappyPath(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryRowFn: func(sqlStr string, args ...any) pg.Row {
			if !contains(sqlStr, "FROM hitl_decision_log") {
				t.Errorf("expected FROM hitl_decision_log; got %q", sqlStr)
			}
			return &stubRow{scan: func(dest ...any) error {
				*(dest[0].(*string)) = "event-1"
				*(dest[1].(*string)) = "tenant-1"
				*(dest[2].(*string)) = "dec-1"
				*(dest[3].(*string)) = "run-1"
				// operator_gcid is now scanned as sql.NullString (nullable
				// since migration 0010 — pending gates carry NULL).
				*(dest[4].(*sql.NullString)) = sql.NullString{String: "op-1", Valid: true}
				*(dest[5].(*sql.NullString)) = sql.NullString{}
				*(dest[6].(*string)) = "approve"
				*(dest[7].(*string)) = "hitl_l1"
				*(dest[8].(*string)) = `{}`
				*(dest[9].(*string)) = "runtime"
				*(dest[10].(*time.Time)) = now
				return nil
			}}
		},
	}
	repo := pg.NewEvidenceRepository(q)
	got, err := repo.LoadHITLDecision(context.Background(), "tenant-1", "dec-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DecisionID != "dec-1" {
		t.Errorf("DecisionID = %q; want dec-1", got.DecisionID)
	}
	if got.OperatorGcid != "op-1" {
		t.Errorf("OperatorGcid = %q; want op-1 (NullString valid)", got.OperatorGcid)
	}
}

// TestEvidenceRepository_LoadHITLDecision_NullOperator asserts a PENDING gate's
// NULL operator_gcid (migration 0010) surfaces as an empty string, not a scan
// error.
func TestEvidenceRepository_LoadHITLDecision_NullOperator(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryRowFn: func(sqlStr string, args ...any) pg.Row {
			return &stubRow{scan: func(dest ...any) error {
				*(dest[0].(*string)) = "event-1"
				*(dest[1].(*string)) = "tenant-1"
				*(dest[2].(*string)) = "dec-pending-1"
				*(dest[3].(*string)) = "run-1"
				*(dest[4].(*sql.NullString)) = sql.NullString{} // NULL operator (pending)
				*(dest[5].(*sql.NullString)) = sql.NullString{}
				*(dest[6].(*string)) = "pending"
				*(dest[7].(*string)) = "hitl_l0"
				*(dest[8].(*string)) = `{}`
				*(dest[9].(*string)) = "runtime"
				*(dest[10].(*time.Time)) = now
				return nil
			}}
		},
	}
	repo := pg.NewEvidenceRepository(q)
	got, err := repo.LoadHITLDecision(context.Background(), "tenant-1", "dec-pending-1")
	if err != nil {
		t.Fatalf("Load (pending, null operator): %v", err)
	}
	if got.OperatorGcid != "" {
		t.Errorf("OperatorGcid = %q; want empty (NULL operator on pending gate)", got.OperatorGcid)
	}
	if got.Decision != evidence.HitlPending {
		t.Errorf("Decision = %q; want pending", got.Decision)
	}
}

// -----------------------------------------------------------------------------
// HITLDecision — UpdateAssigneeGcid (N7)
// -----------------------------------------------------------------------------

func TestEvidenceRepository_UpdateAssigneeGcid_EmitsUpdate(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	alice := "alice-gcid"
	if err := repo.UpdateAssigneeGcid(context.Background(), "tenant-1", "dec-1", &alice, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAssigneeGcid: %v", err)
	}
	if !contains(q.execSQL, "UPDATE hitl_decision_log") {
		t.Errorf("expected UPDATE hitl_decision_log; got %q", q.execSQL)
	}
	if !contains(q.execSQL, "assignee_gcid") {
		t.Errorf("expected assignee_gcid column in SQL; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_UpdateAssigneeGcid_ClearsToNull(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.UpdateAssigneeGcid(context.Background(), "tenant-1", "dec-1", nil, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAssigneeGcid clear: %v", err)
	}
	if !contains(q.execSQL, "UPDATE hitl_decision_log") {
		t.Errorf("expected UPDATE hitl_decision_log on clear; got %q", q.execSQL)
	}
}

func TestEvidenceRepository_UpdateAssigneeGcid_ErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{execErr: errors.New("db down")}
	repo := pg.NewEvidenceRepository(q)
	alice := "alice-gcid"
	err := repo.UpdateAssigneeGcid(context.Background(), "tenant-1", "dec-1", &alice, time.Now().UTC())
	if err == nil {
		t.Fatal("expected error to surface")
	}
}

func TestEvidenceRepository_QueryPolicyViolations_ScansRow(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "a1", "pii.dlp", "high", "dlp",
					`{}`, "runtime", now,
				},
			}}, nil
		},
	}
	repo := pg.NewEvidenceRepository(q)
	out, err := repo.QueryPolicyViolations(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 1 || out[0].Severity != "high" {
		t.Errorf("got %+v", out)
	}
}

func TestEvidenceRepository_UpsertCircuitBreaker_ExecError(t *testing.T) {
	t.Parallel()
	cb := evidence.NewCircuitBreaker(uuid.NewString(), "agent-1")
	q := &stubQuerier{execErr: errors.New("db down")}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.UpsertCircuitBreaker(context.Background(), cb); err == nil {
		t.Fatal("expected error to surface")
	}
}

func TestEvidenceRepository_UpsertQuarantine_ExecError(t *testing.T) {
	t.Parallel()
	qe := evidence.NewQuarantine(uuid.NewString(), "agent-1", "reason")
	q := &stubQuerier{execErr: errors.New("db down")}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.UpsertQuarantine(context.Background(), qe); err == nil {
		t.Fatal("expected error to surface")
	}
}

func TestEvidenceRepository_UpsertQuarantine_WithReleasedAt(t *testing.T) {
	t.Parallel()
	qe := evidence.NewQuarantine(uuid.NewString(), "agent-1", "reason")
	qe.Release()
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.UpsertQuarantine(context.Background(), qe); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Released quarantine should still emit insert; released_at is the
	// last positional arg.
	if !contains(q.execSQL, "INSERT INTO quarantine_state") {
		t.Errorf("expected INSERT INTO quarantine_state; got %q", q.execSQL)
	}
}

// -----------------------------------------------------------------------------
// jsonbArg + decodeMap helpers
// -----------------------------------------------------------------------------

func TestEvidenceRepository_JSONHelpersHandleEmptyAndInvalid(t *testing.T) {
	t.Parallel()
	// Exercise via AppendAccountability (Provenance gets jsonbArg'd inside).
	a := newAccountability(t)
	a.Provenance = nil // empty path
	q := &stubQuerier{}
	repo := pg.NewEvidenceRepository(q)
	if err := repo.AppendAccountability(context.Background(), a); err != nil {
		t.Fatalf("Append nil provenance: %v", err)
	}
	// Now query with a malformed JSON row — decodeMap returns empty map.
	q2 := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{
				{
					"event-1", "tenant-1", "agent-1", "owner-1",
					"dec-1", "type-1",
					`{not-json`, "hash-1",
					"runtime", "", time.Now().UTC(),
				},
			}}, nil
		},
	}
	repo2 := pg.NewEvidenceRepository(q2)
	out, err := repo2.QueryAccountability(context.Background(), evidence.QueryFilter{})
	if err != nil {
		t.Fatalf("Query bad JSON: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row; got %d", len(out))
	}
	// decodeMap returns empty map on malformed JSON.
	if len(out[0].Provenance) != 0 {
		t.Errorf("expected empty map on bad JSON; got %+v", out[0].Provenance)
	}
}

// -----------------------------------------------------------------------------
// Compile-time interface check
// -----------------------------------------------------------------------------

func TestEvidenceRepository_SatisfiesInterface(t *testing.T) {
	t.Parallel()
	var _ evidence.Repository = (*pg.EvidenceRepository)(nil)
}
