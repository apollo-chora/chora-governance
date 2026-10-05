// security_tail_test.go — coverage tail for the pg adapters using the shared
// stubQuerier (package pg_test): audit VerifyChain chain walks, the Append*
// error branches (exec failure, idempotent-duplicate, nil arg), the IMDA
// Dashboard placeholder/error paths, policy Save/FindApplicable scan errors,
// the AI-transparency repo error branches, and the PgxPoolQuerier surface
// errors.
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/aitransparency"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

// -----------------------------------------------------------------------------
// audit VerifyChain
// -----------------------------------------------------------------------------

// verifyRow builds one stubRows row (18 columns, matching audit.Query's
// SELECT list).
func verifyRow(e *audit.Event) []any {
	return []any{
		e.EventID, e.TenantID, e.Gcid, e.Agid,
		e.Action, e.Resource, string(e.Decision), e.Reason,
		e.SubjectType, e.SubjectID, e.ActorGcid,
		e.Before, e.After,
		e.Traceparent, e.Tracestate,
		e.PrevHash, e.EntryHash, e.CreatedAt,
	}
}

func chainedPair(t *testing.T) (*audit.Event, *audit.Event) {
	t.Helper()
	base := &audit.Event{EventID: "e1", TenantID: "t1", Gcid: "g1", Action: "read",
		Decision: audit.DecisionPermitted, CreatedAt: time.Now().UTC()}
	e1 := *base
	e1.EntryHash = audit.ComputeHash(&e1, "")
	e2 := *base
	e2.EventID = "e2"
	e2.PrevHash = e1.EntryHash
	e2.EntryHash = audit.ComputeHash(&e2, e1.EntryHash)
	return &e1, &e2
}

func TestAuditVerifyChain_ValidChain(t *testing.T) {
	t.Parallel()
	e1, e2 := chainedPair(t)
	q := &stubQuerier{
		queryFn: func(string, ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{verifyRow(e1), verifyRow(e2)}}, nil
		},
	}
	repo := pg.NewAuditRepository(q)
	res, err := repo.VerifyChain(context.Background(), "t1")
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Valid || res.Verified != 2 {
		t.Errorf("valid chain: res=%+v", res)
	}
}

func TestAuditVerifyChain_BrokenPrevHash(t *testing.T) {
	t.Parallel()
	e1, e2 := chainedPair(t)
	e2.PrevHash = "tampered"
	q := &stubQuerier{
		queryFn: func(string, ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{verifyRow(e1), verifyRow(e2)}}, nil
		},
	}
	repo := pg.NewAuditRepository(q)
	res, err := repo.VerifyChain(context.Background(), "t1")
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Valid || res.FirstBrokenEventID != "e2" || res.BrokenAtIndex != 1 {
		t.Errorf("broken prev-hash: res=%+v", res)
	}
}

func TestAuditVerifyChain_BrokenEntryHash(t *testing.T) {
	t.Parallel()
	e1, e2 := chainedPair(t)
	e2.EntryHash = "tampered"
	q := &stubQuerier{
		queryFn: func(string, ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{verifyRow(e1), verifyRow(e2)}}, nil
		},
	}
	repo := pg.NewAuditRepository(q)
	res, err := repo.VerifyChain(context.Background(), "t1")
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Valid || res.FirstBrokenEventID != "e2" {
		t.Errorf("broken entry-hash: res=%+v", res)
	}
}

func TestAuditVerifyChain_QueryError(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(string, ...any) (pg.Rows, error) {
			return nil, errors.New("query boom")
		},
	}
	repo := pg.NewAuditRepository(q)
	if _, err := repo.VerifyChain(context.Background(), "t1"); err == nil {
		t.Error("query error should propagate")
	}
}

// -----------------------------------------------------------------------------
// evidence Append error branches
// -----------------------------------------------------------------------------

func TestEvidenceAppends_ErrorBranches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// nil args → typed errors (covers the nil guard of each Append)
	repo := pg.NewEvidenceRepository(&stubQuerier{})
	nilCases := []struct {
		name string
		run  func() error
	}{
		{"DataCard", func() error { return repo.AppendDataCard(ctx, nil) }},
		{"DecisionExplanation", func() error { return repo.AppendDecisionExplanation(ctx, nil) }},
		{"RedTeamRun", func() error { return repo.AppendRedTeamRun(ctx, nil) }},
		{"EvalRun", func() error { return repo.AppendEvalRun(ctx, nil) }},
		{"CostAnomaly", func() error { return repo.AppendCostAnomaly(ctx, nil) }},
		{"BiasTestRun", func() error { return repo.AppendBiasTestRun(ctx, nil) }},
		{"PolicyViolation", func() error { return repo.AppendPolicyViolation(ctx, nil) }},
		{"HITLDecision", func() error { return repo.AppendHITLDecision(ctx, nil) }},
	}
	for _, tc := range nilCases {
		if err := tc.run(); err == nil {
			t.Errorf("%s nil arg should error", tc.name)
		}
	}

	// exec-error with duplicate hint → treated as idempotent no-op success
	dupe := &stubQuerier{execErr: errors.New("duplicate key value violates unique constraint \"event_id\"")}
	rr := pg.NewEvidenceRepository(dupe)
	if err := rr.AppendDataCard(ctx, &evidence.DataCard{}); err != nil {
		t.Errorf("duplicate append should be a no-op: %v", err)
	}

	// exec-error without duplicate hint → wrapped error
	boom := &stubQuerier{execErr: errors.New("connection refused")}
	br := pg.NewEvidenceRepository(boom)
	if err := br.AppendDataCard(ctx, &evidence.DataCard{}); err == nil {
		t.Error("non-duplicate exec error should propagate")
	}
	if err := br.AppendDecisionExplanation(ctx, &evidence.DecisionExplanation{}); err == nil {
		t.Error("non-duplicate exec error (explanation) should propagate")
	}

	// IMDA append errors
	imdaRepo := pg.NewIMDARepository(&stubQuerier{execErr: errors.New("boom")})
	if err := imdaRepo.Append(ctx, nil); err == nil {
		t.Error("imda nil append should error")
	}
	if err := imdaRepo.Append(ctx, &imda.Assessment{}); err == nil {
		t.Error("imda exec error should propagate")
	}
}

// -----------------------------------------------------------------------------
// IMDA Dashboard placeholder + error paths
// -----------------------------------------------------------------------------

func TestIMDADashboard_PlaceholdersForMissingDimensions(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{queryFn: func(string, ...any) (pg.Rows, error) {
		return &stubRows{}, nil // zero rows → all placeholders
	}}
	repo := pg.NewIMDARepository(q)
	dash, err := repo.Dashboard(context.Background(), "t1")
	if err != nil {
		t.Fatalf("Dashboard: %v", err)
	}
	if len(dash) != 4 {
		t.Fatalf("dash = %d; want 4 placeholders", len(dash))
	}
	for _, a := range dash {
		if a.Score != 0 || a.AssessmentID != "" {
			t.Errorf("placeholder wrong: %+v", a)
		}
	}
}

func TestIMDADashboard_QueryErrorAndScanError(t *testing.T) {
	t.Parallel()
	// query error
	repo := pg.NewIMDARepository(&stubQuerier{queryFn: func(string, ...any) (pg.Rows, error) {
		return nil, errors.New("boom")
	}})
	if _, err := repo.Dashboard(context.Background(), "t1"); err == nil {
		t.Error("query error should propagate")
	}

	// rows.Err() after iteration
	repo = pg.NewIMDARepository(&stubQuerier{queryFn: func(string, ...any) (pg.Rows, error) {
		return &stubRows{iterErr: errors.New("iter boom")}, nil
	}})
	if _, err := repo.Dashboard(context.Background(), "t1"); err == nil {
		t.Error("iter error should propagate")
	}
}

// -----------------------------------------------------------------------------
// policy repo error branches
// -----------------------------------------------------------------------------

func TestPolicyRepository_SaveNilRule(t *testing.T) {
	t.Parallel()
	repo := pg.NewPolicyRepository(&stubQuerier{})
	if err := repo.Save(context.Background(), nil); err == nil {
		t.Error("nil rule should error")
	}
}

func TestPolicyRepository_FindApplicable_ScanAndIterErrors(t *testing.T) {
	t.Parallel()
	// scan error
	repo := pg.NewPolicyRepository(&stubQuerier{queryFn: func(string, ...any) (pg.Rows, error) {
		return &stubRows{rows: [][]any{{
			"r1", "t1", "n", "", `[]`, "allowed", true, 1,
			time.Now(), time.Now(),
		}}, scanErr: errors.New("scan boom")}, nil
	}})
	if _, err := repo.FindApplicable(context.Background(), "t1"); err == nil {
		t.Error("scan error should propagate")
	}

	// rows.Err()
	repo = pg.NewPolicyRepository(&stubQuerier{queryFn: func(string, ...any) (pg.Rows, error) {
		return &stubRows{iterErr: errors.New("iter boom")}, nil
	}})
	if _, err := repo.FindApplicable(context.Background(), "t1"); err == nil {
		t.Error("iter error should propagate")
	}
}

// -----------------------------------------------------------------------------
// ai-transparency repo branches
// -----------------------------------------------------------------------------

func TestAITransparency_ActiveDisclosureVersion_NoRowsAndRow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// ErrNoRows → ErrNoActiveDisclosure
	repo := pg.NewAiTransparencyRepository(&stubQuerier{
		queryRowFn: func(string, ...any) pg.Row { return &stubRow{err: pg.ErrNoRows} },
	})
	if _, err := repo.ActiveDisclosureVersion(ctx); !errors.Is(err, aitransparency.ErrNoActiveDisclosure) {
		t.Errorf("no rows err = %v; want ErrNoActiveDisclosure", err)
	}

	// non-ErrNoRows scan error → wrapped
	repo = pg.NewAiTransparencyRepository(&stubQuerier{
		queryRowFn: func(string, ...any) pg.Row { return &stubRow{err: errors.New("boom")} },
	})
	if _, err := repo.ActiveDisclosureVersion(ctx); err == nil {
		t.Error("scan error should propagate")
	}

	// successful row with empty locales JSON
	repo = pg.NewAiTransparencyRepository(&stubQuerier{
		queryRowFn: func(string, ...any) pg.Row {
			return &stubRow{scan: func(dest ...any) error {
				*dest[0].(*string) = "2026-07-01"
				*dest[1].(*string) = string(aitransparency.StatusActive)
				*dest[2].(*bool) = true
				*dest[3].(*time.Time) = time.Now().UTC()
				*dest[4].(*string) = "platform"
				*dest[5].(*string) = ""
				*dest[6].(*string) = "g1"
				*dest[7].(*string) = "g2"
				return nil
			}}
		},
	})
	v, err := repo.ActiveDisclosureVersion(ctx)
	if err != nil {
		t.Fatalf("ActiveDisclosureVersion: %v", err)
	}
	if v.Version != "2026-07-01" || len(v.Locales) != 0 {
		t.Errorf("version=%q locales=%v", v.Version, v.Locales)
	}
}

func TestAITransparency_LatestAcknowledgement_Errors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// ErrNoRows → ErrNotFound
	repo := pg.NewAiTransparencyRepository(&stubQuerier{
		queryRowFn: func(string, ...any) pg.Row { return &stubRow{err: pg.ErrNoRows} },
	})
	if _, err := repo.LatestAcknowledgement(ctx, "g1", "t1"); !errors.Is(err, aitransparency.ErrNotFound) {
		t.Errorf("no rows err = %v; want ErrNotFound", err)
	}

	// other error → wrapped
	repo = pg.NewAiTransparencyRepository(&stubQuerier{
		queryRowFn: func(string, ...any) pg.Row { return &stubRow{err: errors.New("boom")} },
	})
	if _, err := repo.LatestAcknowledgement(ctx, "g1", "t1"); err == nil {
		t.Error("scan error should propagate")
	}
}

func TestAITransparency_AppendAcknowledgement_NilAndError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := pg.NewAiTransparencyRepository(&stubQuerier{})
	if err := repo.AppendAcknowledgement(ctx, nil); err == nil {
		t.Error("nil ack should error")
	}
	repo = pg.NewAiTransparencyRepository(&stubQuerier{execErr: errors.New("boom")})
	if err := repo.AppendAcknowledgement(ctx, &aitransparency.Acknowledgement{}); err == nil {
		t.Error("exec error should propagate")
	}
}
