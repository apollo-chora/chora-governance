// Package audit_test exercises AuditEvent invariants.
//
// AuditEvent is APPEND-ONLY per the spec: never UPDATE existing.
package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	gcidA   = "01970000-0000-7000-9000-000000000001"
	agidA   = "01970000-0000-7000-a000-000000000001"
)

// -----------------------------------------------------------------------------
// New / construction
// -----------------------------------------------------------------------------

func TestNew_AssignsUUIDv7EventID(t *testing.T) {
	t.Parallel()
	e, err := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA,
		Action: "atom.create", Resource: "learningatom",
		Decision: audit.DecisionPermitted,
	})
	if err != nil {
		t.Fatalf("New() unexpected: %v", err)
	}
	if len(e.EventID) != 36 {
		t.Errorf("EventID length = %d; want 36", len(e.EventID))
	}
	if e.EventID[14] != '7' {
		t.Errorf("EventID version char = %q; want '7'", string(e.EventID[14]))
	}
}

func TestNew_SetsCreatedAtToNow(t *testing.T) {
	t.Parallel()
	before := time.Now().UTC()
	e, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA,
		Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
	})
	after := time.Now().UTC()
	if e.CreatedAt.Before(before) || e.CreatedAt.After(after) {
		t.Errorf("CreatedAt = %v; want between %v and %v", e.CreatedAt, before, after)
	}
}

func TestNew_AcceptsNullAgid(t *testing.T) {
	t.Parallel()
	e, err := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA, Agid: "",
		Action: "x", Resource: "y", Decision: audit.DecisionDenied,
	})
	if err != nil {
		t.Fatalf("nullable agid should be accepted: %v", err)
	}
	if e.Agid != "" {
		t.Errorf("Agid = %q; want empty when omitted", e.Agid)
	}
}

func TestNew_PropagatesAgidWhenSet(t *testing.T) {
	t.Parallel()
	e, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA, Agid: agidA,
		Action: "x", Resource: "y", Decision: audit.DecisionDenied,
	})
	if e.Agid != agidA {
		t.Errorf("Agid = %q; want %q", e.Agid, agidA)
	}
}

func TestNew_RejectsMissingTenantID(t *testing.T) {
	t.Parallel()
	_, err := audit.New(audit.NewParams{
		TenantID: "", Gcid: gcidA, Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
	})
	if err == nil {
		t.Errorf("expected error for missing TenantID; got nil")
	}
}

func TestNew_RejectsMissingGcid(t *testing.T) {
	t.Parallel()
	_, err := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: "", Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
	})
	if err == nil {
		t.Errorf("expected error for missing Gcid; got nil")
	}
}

func TestNew_RejectsMissingAction(t *testing.T) {
	t.Parallel()
	_, err := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA, Action: "", Resource: "y", Decision: audit.DecisionPermitted,
	})
	if err == nil {
		t.Errorf("expected error for missing Action; got nil")
	}
}

func TestNew_RejectsInvalidDecision(t *testing.T) {
	t.Parallel()
	_, err := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA, Action: "x", Resource: "y", Decision: "shrug",
	})
	if err == nil {
		t.Errorf("expected error for invalid decision; got nil")
	}
}

func TestDecision_Valid(t *testing.T) {
	t.Parallel()
	if !audit.DecisionPermitted.Valid() || !audit.DecisionDenied.Valid() {
		t.Errorf("permitted and denied should be valid")
	}
	if audit.Decision("nope").Valid() {
		t.Errorf("invalid decision should fail")
	}
}

// -----------------------------------------------------------------------------
// Append-only invariant
// -----------------------------------------------------------------------------

// TestRepository_AppendAndQuery exercises the in-memory repository's Append
// + Query semantics. Append-only: callers cannot mutate stored events.
func TestRepository_AppendAndQuery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := audit.NewInMemoryRepository()

	e, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA,
		Action: "atom.create", Resource: "learningatom",
		Decision: audit.DecisionPermitted,
	})
	if err := r.Append(ctx, e); err != nil {
		t.Fatalf("Append unexpected: %v", err)
	}

	out, err := r.Query(ctx, audit.QueryFilter{TenantID: tenantA})
	if err != nil {
		t.Fatalf("Query unexpected: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("Query returned %d events; want 1", len(out))
	}
	if out[0].EventID != e.EventID {
		t.Errorf("Query mismatch: got %s want %s", out[0].EventID, e.EventID)
	}
}

func TestRepository_AppendOnly_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := audit.NewInMemoryRepository()

	e, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA,
		Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
	})
	if err := r.Append(ctx, e); err != nil {
		t.Fatalf("Append unexpected: %v", err)
	}
	// Re-appending the same event_id is an attempted UPDATE — must fail.
	if err := r.Append(ctx, e); err == nil {
		t.Errorf("re-Appending same event_id should fail (append-only); got nil")
	}
}

func TestRepository_TenantIsolation(t *testing.T) {
	t.Parallel()
	tenantB := "01970000-0000-7000-8000-000000000002"

	ctx := context.Background()
	r := audit.NewInMemoryRepository()
	eA, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA, Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
	})
	eB, _ := audit.New(audit.NewParams{
		TenantID: tenantB, Gcid: gcidA, Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
	})
	_ = r.Append(ctx, eA)
	_ = r.Append(ctx, eB)

	out, _ := r.Query(ctx, audit.QueryFilter{TenantID: tenantA})
	if len(out) != 1 {
		t.Errorf("Query(tenantA) returned %d; want 1", len(out))
	}
	for _, ev := range out {
		if ev.TenantID != tenantA {
			t.Errorf("cross-tenant leak: got tenant %q in tenantA query", ev.TenantID)
		}
	}
}

func TestRepository_Query_FilterByTimeRange(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := audit.NewInMemoryRepository()

	now := time.Now().UTC()
	e, _ := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA,
		Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
	})
	_ = r.Append(ctx, e)

	// Query with from in the future — should return no events
	future := now.Add(24 * time.Hour)
	out, _ := r.Query(ctx, audit.QueryFilter{TenantID: tenantA, From: &future})
	if len(out) != 0 {
		t.Errorf("future from-filter returned %d; want 0", len(out))
	}

	// Query with to in the past — should return no events
	past := now.Add(-24 * time.Hour)
	out2, _ := r.Query(ctx, audit.QueryFilter{TenantID: tenantA, To: &past})
	if len(out2) != 0 {
		t.Errorf("past to-filter returned %d; want 0", len(out2))
	}
}

func TestRepository_Query_RespectsLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := audit.NewInMemoryRepository()

	for i := 0; i < 5; i++ {
		e, _ := audit.New(audit.NewParams{
			TenantID: tenantA, Gcid: gcidA,
			Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
		})
		_ = r.Append(ctx, e)
	}
	out, _ := r.Query(ctx, audit.QueryFilter{TenantID: tenantA, Limit: 3})
	if len(out) != 3 {
		t.Errorf("Query(limit=3) returned %d; want 3", len(out))
	}
}

func TestNew_PreservesTraceparentAndTracestate(t *testing.T) {
	t.Parallel()
	tp := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	ts := "rojo=00f067aa0ba902b7"
	e, err := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA,
		Action: "x", Resource: "y", Decision: audit.DecisionPermitted,
		Traceparent: tp, Tracestate: ts,
	})
	if err != nil {
		t.Fatalf("New() unexpected: %v", err)
	}
	if e.Traceparent != tp {
		t.Errorf("Traceparent not preserved: got %q want %q", e.Traceparent, tp)
	}
	if e.Tracestate != ts {
		t.Errorf("Tracestate not preserved: got %q want %q", e.Tracestate, ts)
	}
}
