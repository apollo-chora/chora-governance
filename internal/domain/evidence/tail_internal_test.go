// tail_internal_test.go — INTERNAL (package evidence) coverage tail for the
// unexported helpers + small verdict branches the external suite reaches only
// partially: IsPending/Valid edge cases, noteFromEditPayload, moreCurrentHITL,
// NewPendingHITLDecision guard rails, Claim/Release error text, and the
// repository Query limit/offset/bad-filter paths.
package evidence

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestInternal_HitlVerdict_IsPendingAndValid(t *testing.T) {
	t.Parallel()
	if !HitlPending.IsPending() {
		t.Error("pending sentinel should be pending")
	}
	if !HitlVerdict("").IsPending() {
		t.Error("empty verdict should be pending (legacy rows)")
	}
	if HitlApprove.IsPending() {
		t.Error("approve must not be pending")
	}
	if HitlVerdict("approved").Valid() {
		t.Error("non-canonical verdict must be invalid")
	}
	if HitlPending.Valid() {
		t.Error("pending must not be a terminal-valid verdict")
	}
	if AutonomyLevel("hitl_l3").Valid() {
		t.Error("level 3 autonomy must be rejected")
	}
	if AutonomyLevel("").Valid() {
		t.Error("empty autonomy level must be invalid")
	}
}

func TestInternal_NoteFromEditPayload_Branches(t *testing.T) {
	t.Parallel()
	if noteFromEditPayload(nil) != "" {
		t.Error("nil map → empty")
	}
	if noteFromEditPayload(map[string]any{NoteEditPayloadKey: "note here"}) != "note here" {
		t.Error("string note should pass through")
	}
	if noteFromEditPayload(map[string]any{NoteEditPayloadKey: 7}) != "" {
		t.Error("non-string note → empty")
	}
}

func TestInternal_MoreCurrentHITL(t *testing.T) {
	t.Parallel()
	earlier := time.Now().UTC().Add(-time.Hour)
	base := &HITLDecision{Decision: HitlPending, DecidedAt: earlier}

	// terminal supersedes pending
	term := &HITLDecision{Decision: HitlApprove, DecidedAt: earlier}
	if !moreCurrentHITL(term, base) || moreCurrentHITL(base, term) {
		t.Error("terminal should supersede pending in both directions")
	}
	// later DecidedAt wins among same terminality
	otherPending := &HITLDecision{Decision: HitlVerdict("pending"), DecidedAt: time.Now()}
	if !moreCurrentHITL(otherPending, base) {
		t.Error("later pending row should win")
	}
	if moreCurrentHITL(base, otherPending) {
		t.Error("earlier row should not win")
	}
	// same terminality + same timestamp → no winner
	same := &HITLDecision{Decision: HitlPending, DecidedAt: base.DecidedAt}
	if moreCurrentHITL(same, base) {
		t.Error("same-timestamp row should not be more current")
	}
}

func TestInternal_NewPendingHITLDecision_Validation(t *testing.T) {
	t.Parallel()
	d, err := NewPendingHITLDecision(PendingHITLDecisionParams{
		EventID: "e1", TenantID: "t1", DecisionID: "d1", RunID: "r1",
		AutonomyLevel: AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if d.Decision != HitlPending || d.OperatorGcid != "" || d.AssigneeGcid != nil {
		t.Errorf("pending row fields wrong: %+v", d)
	}

	if _, err := NewPendingHITLDecision(PendingHITLDecisionParams{}); err == nil {
		t.Error("empty params should error")
	}
}

func TestInternal_HITLDecision_ClaimAndRelease_TrimmedGCID(t *testing.T) {
	t.Parallel()
	d, err := NewPendingHITLDecision(PendingHITLDecisionParams{
		EventID: "e1", TenantID: "t1", DecisionID: "d1", RunID: "r1",
		AutonomyLevel: AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if err := d.Claim("  gcid-1  ", time.Now()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := d.Release(" gcid-1 ", time.Now()); err != nil {
		t.Fatalf("Release by assignee: %v", err)
	}
}

func TestInternal_InMemoryQuery_FilterBranches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := NewInMemoryRepository()

	seed := func(i int) {
		mc, err := NewModelCard(ModelCardParams{
			EventID: "mc" + itoa(i), TenantID: "t1", ModelID: "m", ModelVersion: "1",
			CardMD: "c", TrainingDataSummary: "s", IntendedUses: "u", Limitations: "l",
		})
		if err != nil {
			t.Fatalf("NewModelCard: %v", err)
		}
		if err := repo.AppendModelCard(ctx, mc); err != nil {
			t.Fatalf("AppendModelCard: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		seed(i)
	}

	// limit + offset slicing
	rows, err := repo.QueryModelCards(ctx, QueryFilter{TenantID: "t1", Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("QueryModelCards: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("limit/offset → %d rows; want 2", len(rows))
	}
	// offset beyond size → empty
	rows, err = repo.QueryModelCards(ctx, QueryFilter{TenantID: "t1", Offset: 99})
	if err != nil {
		t.Fatalf("QueryModelCards: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("offset beyond → %d rows; want 0", len(rows))
	}

	// bad lifecycle filter matches nothing
	if got, _ := repo.QueryModelCards(ctx, QueryFilter{TenantID: "t1", LifecycleStage: LifecyclePostDeploy}); len(got) != 0 {
		t.Errorf("lifecycle filter → %d rows; want 0", len(got))
	}
	// lifecycle match works
	if got, _ := repo.QueryModelCards(ctx, QueryFilter{TenantID: "t1", LifecycleStage: LifecycleRuntime}); len(got) != 5 {
		t.Errorf("lifecycle runtime → %d rows; want 5", len(got))
	}
}

// itoa is a tiny int→string helper (mirrors the rubric test helper).
func itoa(i int) string {
	return strings.TrimSpace(string(rune('0' + i)))
}

func TestInternal_LoadHITLDecision_ResolvesToTerminal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := NewInMemoryRepository()

	// two rows for the same decision_id — one pending, one terminal
	pending, err := NewPendingHITLDecision(PendingHITLDecisionParams{
		EventID: "pend-1", TenantID: "t1", DecisionID: "d1", RunID: "r1",
		AutonomyLevel: AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	if err := repo.AppendHITLDecision(ctx, pending); err != nil {
		t.Fatalf("Append pending: %v", err)
	}
	terminal, err := NewPendingHITLDecision(PendingHITLDecisionParams{
		EventID: "term-1", TenantID: "t1", DecisionID: "d1", RunID: "r1",
		AutonomyLevel: AutonomyHitlL1,
	})
	if err != nil {
		t.Fatalf("NewPendingHITLDecision: %v", err)
	}
	terminal.Decision = HitlApprove
	terminal.OperatorGcid = "op-1"
	if err := repo.AppendHITLDecision(ctx, terminal); err != nil {
		t.Fatalf("Append terminal: %v", err)
	}

	loaded, err := repo.LoadHITLDecision(ctx, "t1", "d1")
	if err != nil {
		t.Fatalf("LoadHITLDecision: %v", err)
	}
	if loaded.Decision != HitlApprove || loaded.EventID != "term-1" {
		t.Errorf("resolved row = %+v; want the terminal row", loaded)
	}
	if _, err := repo.LoadHITLDecision(ctx, "t-other", "d1"); !isNotFound(err) {
		t.Errorf("cross-tenant lookup err = %v; want ErrNotFound", err)
	}
}

func isNotFound(err error) bool {
	return err == ErrNotFound
}
