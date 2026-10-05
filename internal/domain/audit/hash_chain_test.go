// Package audit_test — hash-chain tamper-evidence tests.
//
// Each appended entry carries entry_hash = SHA-256(canonical(entry) || prev_hash).
// Tampering with any entry breaks all subsequent entries' hashes; verification
// detects this.
package audit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

func mkEvent(t *testing.T, action string) *audit.Event {
	t.Helper()
	e, err := audit.New(audit.NewParams{
		TenantID: tenantA, Gcid: gcidA,
		Action: action, Resource: "x",
		Decision: audit.DecisionPermitted,
	})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	return e
}

// -----------------------------------------------------------------------------
// ComputeHash
// -----------------------------------------------------------------------------

func TestComputeHash_DeterministicForSameInputs(t *testing.T) {
	t.Parallel()
	e := mkEvent(t, "atom.create")
	h1 := audit.ComputeHash(e, "")
	h2 := audit.ComputeHash(e, "")
	if h1 != h2 {
		t.Errorf("ComputeHash should be deterministic: %s vs %s", h1, h2)
	}
}

func TestComputeHash_DiffersWhenPrevHashChanges(t *testing.T) {
	t.Parallel()
	e := mkEvent(t, "atom.create")
	h1 := audit.ComputeHash(e, "")
	h2 := audit.ComputeHash(e, "deadbeef")
	if h1 == h2 {
		t.Errorf("ComputeHash should differ when prev_hash differs")
	}
}

func TestComputeHash_ReturnsHex64(t *testing.T) {
	t.Parallel()
	e := mkEvent(t, "atom.create")
	h := audit.ComputeHash(e, "")
	if len(h) != 64 {
		t.Errorf("ComputeHash length = %d; want 64 (sha256 hex)", len(h))
	}
	if strings.TrimLeft(h, "0123456789abcdef") != "" {
		t.Errorf("ComputeHash should be lowercase hex; got %q", h)
	}
}

// -----------------------------------------------------------------------------
// Repository Append: chains entries via prev_hash + entry_hash
// -----------------------------------------------------------------------------

func TestRepository_AppendComputesEntryHashChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := audit.NewInMemoryRepository()

	e1 := mkEvent(t, "atom.create")
	if err := r.Append(ctx, e1); err != nil {
		t.Fatalf("Append e1: %v", err)
	}

	e2 := mkEvent(t, "atom.publish")
	if err := r.Append(ctx, e2); err != nil {
		t.Fatalf("Append e2: %v", err)
	}

	out, err := r.Query(ctx, audit.QueryFilter{TenantID: tenantA})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len(out) = %d; want 2", len(out))
	}
	if out[0].PrevHash != "" {
		t.Errorf("genesis entry PrevHash = %q; want empty", out[0].PrevHash)
	}
	if out[0].EntryHash == "" {
		t.Errorf("genesis entry EntryHash should be set; got empty")
	}
	if out[1].PrevHash != out[0].EntryHash {
		t.Errorf("e2 PrevHash = %q; want e1 EntryHash %q",
			out[1].PrevHash, out[0].EntryHash)
	}
	if out[1].EntryHash == "" || out[1].EntryHash == out[0].EntryHash {
		t.Errorf("e2 EntryHash should be set and distinct: %q vs %q",
			out[1].EntryHash, out[0].EntryHash)
	}
}

// -----------------------------------------------------------------------------
// Verify: detect tampering
// -----------------------------------------------------------------------------

func TestRepository_VerifyChain_AllValid(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := audit.NewInMemoryRepository()
	for i := 0; i < 4; i++ {
		_ = r.Append(ctx, mkEvent(t, "x"))
	}
	res, err := r.VerifyChain(ctx, tenantA)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Valid {
		t.Errorf("VerifyChain.Valid = false; want true (no tampering): %+v", res)
	}
	if res.Verified != 4 {
		t.Errorf("VerifyChain.Verified = %d; want 4", res.Verified)
	}
}

func TestRepository_VerifyEntry_DetectsModification(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := audit.NewInMemoryRepository()

	e1 := mkEvent(t, "x")
	_ = r.Append(ctx, e1)
	e2 := mkEvent(t, "y")
	_ = r.Append(ctx, e2)

	// Tamper: mutate the stored EntryHash directly via the repo's debug seam.
	r.TamperEntryHash(e1.EventID, "0000000000000000000000000000000000000000000000000000000000000000")

	res, err := r.VerifyChain(ctx, tenantA)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Valid {
		t.Errorf("expected VerifyChain.Valid = false after tampering; got true")
	}
	if res.FirstBrokenEventID == "" {
		t.Errorf("FirstBrokenEventID should be populated when tampering detected")
	}
}

func TestRepository_VerifyEntry_ByID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := audit.NewInMemoryRepository()

	e1 := mkEvent(t, "x")
	_ = r.Append(ctx, e1)

	ok, err := r.VerifyEntry(ctx, e1.EventID)
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
	if !ok {
		t.Errorf("VerifyEntry should be true for untampered entry")
	}

	r.TamperEntryHash(e1.EventID, "tampered-hash")
	ok2, _ := r.VerifyEntry(ctx, e1.EventID)
	if ok2 {
		t.Errorf("VerifyEntry should be false after tampering")
	}
}

func TestRepository_VerifyEntry_UnknownID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r := audit.NewInMemoryRepository()
	_, err := r.VerifyEntry(ctx, "01970000-0000-7000-8000-000000000099")
	if err == nil {
		t.Errorf("VerifyEntry on unknown id should error; got nil")
	}
}
