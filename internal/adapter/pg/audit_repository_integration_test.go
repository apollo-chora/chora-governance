//go:build integration

// audit_repository_integration_test.go — real-Postgres round-trip test for the
// pgx AuditRepository. This gate exists because stub-querier tests cannot
// catch an omitted INSERT column — a silently dropped field survived a whole
// unit suite in another service.
//
// Run with:
//
//	CHORA_TEST_DSN=postgres://chora_governance_app_rw:chora@localhost:5432/chora_governance?sslmode=disable \
//	  go test -tags integration ./internal/adapter/pg/ -run TestIntegration -v
//
// The test skips cleanly when CHORA_TEST_DSN is unset.
package pg_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

// TestIntegration_AuditRepository_AppendQueryRoundTrip writes an audit event
// with every field distinct, reads it back, and compares EVERY field.
func TestIntegration_AuditRepository_AppendQueryRoundTrip(t *testing.T) {
	dsn := os.Getenv("CHORA_TEST_DSN")
	if dsn == "" {
		t.Skip("CHORA_TEST_DSN unset — skipping real-Postgres integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	repo := pg.NewAuditRepository(pg.NewPgxPoolQuerier(pool))

	// Every field distinct so an omitted INSERT column or a swapped Scan
	// destination is caught by the comparison.
	ev, err := audit.New(audit.NewParams{
		TenantID:    uuid.NewString(),
		Gcid:        "01970000-0000-7000-8000-0000000000bb",
		Agid:        "01970000-0000-7000-8000-0000000000cc",
		Action:      "integration_test_action",
		Resource:    "integration.test.resource",
		Decision:    audit.DecisionDenied,
		Reason:      "integration-test-reason",
		SubjectType: "integration_subject",
		SubjectID:   "integration-subject-001",
		ActorGcid:   "01970000-0000-7000-8000-0000000000dd",
		Before:      `{"before":"integration-before"}`,
		After:       `{"after":"integration-after"}`,
		Traceparent: "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
		Tracestate:  "vendor=integration",
	})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}

	if err := repo.Append(ctx, ev); err != nil {
		t.Fatalf("Append: %v", err)
	}

	rows, err := repo.Query(ctx, audit.QueryFilter{TenantID: ev.TenantID})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("Query returned %d rows; want 1", len(rows))
	}
	got := rows[0]

	if got.EventID != ev.EventID {
		t.Errorf("EventID = %q; want %q", got.EventID, ev.EventID)
	}
	if got.TenantID != ev.TenantID {
		t.Errorf("TenantID = %q; want %q", got.TenantID, ev.TenantID)
	}
	if got.Gcid != ev.Gcid {
		t.Errorf("Gcid = %q; want %q", got.Gcid, ev.Gcid)
	}
	if got.Agid != ev.Agid {
		t.Errorf("Agid = %q; want %q", got.Agid, ev.Agid)
	}
	if got.Action != ev.Action {
		t.Errorf("Action = %q; want %q", got.Action, ev.Action)
	}
	if got.Resource != ev.Resource {
		t.Errorf("Resource = %q; want %q", got.Resource, ev.Resource)
	}
	if got.Decision != ev.Decision {
		t.Errorf("Decision = %q; want %q", got.Decision, ev.Decision)
	}
	if got.Reason != ev.Reason {
		t.Errorf("Reason = %q; want %q", got.Reason, ev.Reason)
	}
	if got.SubjectType != ev.SubjectType {
		t.Errorf("SubjectType = %q; want %q", got.SubjectType, ev.SubjectType)
	}
	if got.SubjectID != ev.SubjectID {
		t.Errorf("SubjectID = %q; want %q", got.SubjectID, ev.SubjectID)
	}
	if got.ActorGcid != ev.ActorGcid {
		t.Errorf("ActorGcid = %q; want %q", got.ActorGcid, ev.ActorGcid)
	}
	// before_state / after_state are JSONB columns — Postgres normalises the
	// formatting on store, so compare the parsed JSON, not the raw string.
	if !jsonEqual(got.Before, ev.Before) {
		t.Errorf("Before = %q; want %q (JSONB-normalised)", got.Before, ev.Before)
	}
	if !jsonEqual(got.After, ev.After) {
		t.Errorf("After = %q; want %q (JSONB-normalised)", got.After, ev.After)
	}
	if got.Traceparent != ev.Traceparent {
		t.Errorf("Traceparent = %q; want %q", got.Traceparent, ev.Traceparent)
	}
	if got.Tracestate != ev.Tracestate {
		t.Errorf("Tracestate = %q; want %q", got.Tracestate, ev.Tracestate)
	}
	if got.PrevHash != ev.PrevHash {
		t.Errorf("PrevHash = %q; want %q", got.PrevHash, ev.PrevHash)
	}
	if got.EntryHash != ev.EntryHash {
		t.Errorf("EntryHash = %q; want %q", got.EntryHash, ev.EntryHash)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; want non-zero")
	}

	// Duplicate Append must surface ErrAlreadyExists (unique-violation path).
	if err := repo.Append(ctx, ev); err == nil {
		t.Error("duplicate Append: expected audit.ErrAlreadyExists, got nil")
	} else if err != audit.ErrAlreadyExists {
		t.Errorf("duplicate Append: expected audit.ErrAlreadyExists, got %v", err)
	}
}

// jsonEqual compares two JSON strings semantically (JSONB normalises
// formatting on store, so a byte comparison would false-fail).
func jsonEqual(a, b string) bool {
	if a == b {
		return true
	}
	var ma, mb any
	if json.Unmarshal([]byte(a), &ma) != nil || json.Unmarshal([]byte(b), &mb) != nil {
		return false
	}
	ab, _ := json.Marshal(ma)
	bb, _ := json.Marshal(mb)
	return string(ab) == string(bb)
}

// TestIntegration_AuditRepository_GetByID covers the single-row read path.
// GetByID reads under the platform (NilTenant) scope, so the event is
// inserted with the NilTenantUUID tenant to match that read path.
func TestIntegration_AuditRepository_GetByID(t *testing.T) {
	dsn := os.Getenv("CHORA_TEST_DSN")
	if dsn == "" {
		t.Skip("CHORA_TEST_DSN unset — skipping real-Postgres integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	repo := pg.NewAuditRepository(pg.NewPgxPoolQuerier(pool))

	ev, err := audit.New(audit.NewParams{
		TenantID:    pg.NilTenantUUID,
		Gcid:        "01970000-0000-7000-8000-0000000000ff",
		Action:      "integration_getbyid_action",
		Resource:    "integration.getbyid.resource",
		Decision:    audit.DecisionPermitted,
		Reason:      "integration-getbyid-reason",
		SubjectType: "integration_getbyid_subject",
		SubjectID:   "integration-getbyid-001",
		ActorGcid:   "01970000-0000-7000-8000-000000000099",
		After:       `{"after":"integration-getbyid-after"}`,
		Traceparent: "00-abcdefabcdefabcdefabcdefabcdefabcdef-abcdefabcdefabcdef-01",
	})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	if err := repo.Append(ctx, ev); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := repo.GetByID(ctx, ev.EventID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.EventID != ev.EventID || got.TenantID != ev.TenantID || got.Gcid != ev.Gcid {
		t.Errorf("GetByID mismatch: got %+v", got)
	}
	if got.Action != ev.Action || got.Resource != ev.Resource || got.Decision != ev.Decision {
		t.Errorf("GetByID mismatch: got %+v", got)
	}
	if got.Reason != ev.Reason || got.SubjectType != ev.SubjectType || got.SubjectID != ev.SubjectID {
		t.Errorf("GetByID mismatch: got %+v", got)
	}
	if got.ActorGcid != ev.ActorGcid || !jsonEqual(got.After, ev.After) || got.Traceparent != ev.Traceparent {
		t.Errorf("GetByID mismatch: got %+v", got)
	}
	if got.EntryHash != ev.EntryHash || got.PrevHash != ev.PrevHash {
		t.Errorf("GetByID hash mismatch: got %+v", got)
	}

	// Missing ID → ErrNotFound.
	if _, err := repo.GetByID(ctx, "01970000-0000-7000-8000-00000000dead"); err != audit.ErrNotFound {
		t.Errorf("GetByID(missing): expected audit.ErrNotFound, got %v", err)
	}
}

// TestIntegration_AuditRepository_VerifyChain walks the per-tenant chain.
func TestIntegration_AuditRepository_VerifyChain(t *testing.T) {
	dsn := os.Getenv("CHORA_TEST_DSN")
	if dsn == "" {
		t.Skip("CHORA_TEST_DSN unset — skipping real-Postgres integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	repo := pg.NewAuditRepository(pg.NewPgxPoolQuerier(pool))

	tenantID := uuid.NewString()
	for i := 0; i < 3; i++ {
		ev, err := audit.New(audit.NewParams{
			TenantID: tenantID,
			Gcid:     "01970000-0000-7000-8000-000000000222",
			Action:   "integration_chain_action",
			Resource: "integration.chain.resource",
			Decision: audit.DecisionPermitted,
			Reason:   "chain-" + string(rune('a'+i)),
		})
		if err != nil {
			t.Fatalf("audit.New: %v", err)
		}
		if err := repo.Append(ctx, ev); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}

	res, err := repo.VerifyChain(ctx, tenantID)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Valid {
		t.Errorf("VerifyChain invalid: first broken event %q at index %d", res.FirstBrokenEventID, res.BrokenAtIndex)
	}
	if res.Verified != 3 {
		t.Errorf("VerifyChain verified = %d; want 3", res.Verified)
	}
}
