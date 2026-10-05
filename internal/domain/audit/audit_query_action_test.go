package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

// The O+ egress-audit read (CHO-2245) filters the audit_log to a single
// action discriminator. QueryFilter.Action must scope Query to matching rows
// (and no-filter must still return all).
func TestInMemoryRepository_QueryFilter_Action(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	ctx := context.Background()

	seed := func(action string) {
		ev, err := audit.New(audit.NewParams{
			TenantID: tenantA, Gcid: gcidA, Action: action,
			Resource: "r", Decision: audit.DecisionPermitted,
		})
		if err != nil {
			t.Fatalf("seed new: %v", err)
		}
		if err := repo.Append(ctx, ev); err != nil {
			t.Fatalf("seed append: %v", err)
		}
	}
	seed("external_egress")
	seed("external_egress")
	seed("payments.refund.issued")

	got, err := repo.Query(ctx, audit.QueryFilter{TenantID: tenantA, Action: "external_egress"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Action filter: got %d rows; want 2 external_egress", len(got))
	}
	for _, e := range got {
		if e.Action != "external_egress" {
			t.Errorf("row Action = %q; want external_egress", e.Action)
		}
	}

	all, err := repo.Query(ctx, audit.QueryFilter{TenantID: tenantA})
	if err != nil {
		t.Fatalf("query all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("no-filter: got %d rows; want 3", len(all))
	}
}

// Exercises the remaining QueryFilter branches (SubjectType/SubjectID,
// From/To, Offset, Cursor, Limit) alongside the Action filter so the read-side
// contract the O+ egress read depends on is fully covered.
func TestInMemoryRepository_QueryFilter_AllDimensions(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	ctx := context.Background()

	mk := func(subjectType, subjectID string) *audit.Event {
		ev, err := audit.New(audit.NewParams{
			TenantID: tenantA, Gcid: gcidA, Action: "external_egress",
			Resource: "r", Decision: audit.DecisionPermitted,
			SubjectType: subjectType, SubjectID: subjectID,
		})
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		if err := repo.Append(ctx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
		return ev
	}
	first := mk("agent", "seeker-a")
	mk("agent", "seeker-b")
	mk("familiar", "seeker-a")

	// SubjectType filter.
	agents, _ := repo.Query(ctx, audit.QueryFilter{TenantID: tenantA, SubjectType: "agent"})
	if len(agents) != 2 {
		t.Errorf("SubjectType=agent: got %d; want 2", len(agents))
	}
	// SubjectID filter.
	byID, _ := repo.Query(ctx, audit.QueryFilter{TenantID: tenantA, SubjectID: "seeker-a"})
	if len(byID) != 2 {
		t.Errorf("SubjectID=seeker-a: got %d; want 2", len(byID))
	}
	// From/To window (all rows created ~now).
	now := time.Now().UTC()
	inWindow, _ := repo.Query(ctx, audit.QueryFilter{
		TenantID: tenantA,
		From:     ptr(now.Add(-time.Hour)),
		To:       ptr(now.Add(time.Hour)),
	})
	if len(inWindow) != 3 {
		t.Errorf("From/To window: got %d; want 3", len(inWindow))
	}
	future, _ := repo.Query(ctx, audit.QueryFilter{TenantID: tenantA, From: ptr(now.Add(time.Hour))})
	if len(future) != 0 {
		t.Errorf("From in the future: got %d; want 0", len(future))
	}
	// Limit + Offset.
	limited, _ := repo.Query(ctx, audit.QueryFilter{TenantID: tenantA, Limit: 1})
	if len(limited) != 1 {
		t.Errorf("Limit=1: got %d; want 1", len(limited))
	}
	offset, _ := repo.Query(ctx, audit.QueryFilter{TenantID: tenantA, Offset: 2})
	if len(offset) != 1 {
		t.Errorf("Offset=2: got %d; want 1", len(offset))
	}
	// Cursor — rows AFTER the first event_id (UUIDv7 sortable).
	afterFirst, _ := repo.Query(ctx, audit.QueryFilter{TenantID: tenantA, Cursor: first.EventID})
	if len(afterFirst) != 2 {
		t.Errorf("Cursor after first: got %d; want 2", len(afterFirst))
	}
}

func TestInMemoryRepository_GetByID(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	ctx := context.Background()
	ev, err := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA, Action: "external_egress",
		Resource: "r", Decision: audit.DecisionPermitted,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := repo.Append(ctx, ev); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := repo.GetByID(ctx, ev.EventID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.EventID != ev.EventID || got.Action != "external_egress" {
		t.Errorf("GetByID returned %+v; want event %s", got, ev.EventID)
	}

	if _, err := repo.GetByID(ctx, "01970000-0000-7000-8000-0000deadbeef"); err != audit.ErrNotFound {
		t.Errorf("GetByID(unknown) err = %v; want ErrNotFound", err)
	}
}

func ptr(t time.Time) *time.Time { return &t }
