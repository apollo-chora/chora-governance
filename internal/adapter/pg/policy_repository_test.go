// policy_repository_test.go — pgx adapter tests for policy.Repository using
// the canonical stub Querier pattern from audit_repository_test.go.
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func newRule(t *testing.T, tenantID string) *policy.Rule {
	t.Helper()
	r, err := policy.New(policy.NewParams{
		Name:            "test-rule",
		TenantID:        tenantID,
		EnforcementMode: policy.ModeDeny,
		Conditions: []policy.Condition{
			{Field: "country", Op: policy.OpEquals, Value: "SG"},
		},
	})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return r
}

// -----------------------------------------------------------------------------
// Save (upsert)
// -----------------------------------------------------------------------------

func TestPolicyRepository_Save_NilRejected(t *testing.T) {
	t.Parallel()
	repo := pg.NewPolicyRepository(&stubQuerier{})
	if err := repo.Save(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil rule")
	}
}

func TestPolicyRepository_Save_EmitsInsertOnConflictUpdate(t *testing.T) {
	t.Parallel()
	r := newRule(t, uuid.NewString())
	q := &stubQuerier{}
	repo := pg.NewPolicyRepository(q)
	if err := repo.Save(context.Background(), r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !contains(q.execSQL, "INSERT INTO policy_rules") {
		t.Errorf("expected INSERT INTO policy_rules; got %q", q.execSQL)
	}
	if !contains(q.execSQL, "ON CONFLICT") {
		t.Errorf("expected ON CONFLICT upsert; got %q", q.execSQL)
	}
}

func TestPolicyRepository_Save_GlobalRule_TenantIDNullable(t *testing.T) {
	t.Parallel()
	r := newRule(t, "") // empty tenant_id = global
	q := &stubQuerier{}
	repo := pg.NewPolicyRepository(q)
	if err := repo.Save(context.Background(), r); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// arg index 1 (zero-based) is tenant_id. For global rules the adapter
	// should pass an empty string (the SQL coerces to NULL).
	if q.execArgs[1] != "" {
		t.Errorf("global rule tenant_id arg = %v; want empty string", q.execArgs[1])
	}
}

func TestPolicyRepository_Save_ExecErrorWraps(t *testing.T) {
	t.Parallel()
	r := newRule(t, uuid.NewString())
	q := &stubQuerier{execErr: errors.New("db down")}
	repo := pg.NewPolicyRepository(q)
	if err := repo.Save(context.Background(), r); err == nil {
		t.Fatal("expected error from exec failure")
	}
}

// -----------------------------------------------------------------------------
// Get
// -----------------------------------------------------------------------------

func TestPolicyRepository_Get_NotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: pg.ErrNoRows}
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.Get(context.Background(), uuid.NewString())
	if !errors.Is(err, policy.ErrNotFound) {
		t.Errorf("err = %v; want policy.ErrNotFound", err)
	}
}

func TestPolicyRepository_Get_OtherErrorWraps(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: errors.New("connection refused")}
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.Get(context.Background(), uuid.NewString())
	if err == nil || errors.Is(err, policy.ErrNotFound) {
		t.Errorf("expected wrapped non-ErrNotFound error; got %v", err)
	}
}

func TestPolicyRepository_Get_ScansRow(t *testing.T) {
	t.Parallel()
	ruleID := uuid.NewString()
	now := time.Now().UTC()
	condJSON := `[{"field":"country","op":"equals","value":"SG"}]`
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{scan: func(dest ...any) error {
				*(dest[0].(*string)) = ruleID
				*(dest[1].(*string)) = "" // tenant_id NULL
				*(dest[2].(*string)) = "test-rule"
				*(dest[3].(*string)) = "rationale"
				*(dest[4].(*string)) = condJSON
				*(dest[5].(*string)) = "denied"
				*(dest[6].(*bool)) = true
				*(dest[7].(*int)) = 1
				*(dest[8].(*time.Time)) = now
				*(dest[9].(*time.Time)) = now
				return nil
			}}
		},
	}
	repo := pg.NewPolicyRepository(q)
	got, err := repo.Get(context.Background(), ruleID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RuleID != ruleID {
		t.Errorf("RuleID = %q; want %q", got.RuleID, ruleID)
	}
	if got.Name != "test-rule" {
		t.Errorf("Name = %q", got.Name)
	}
	if !got.IsGlobal() {
		t.Errorf("expected global rule (TenantID empty); got %q", got.TenantID)
	}
	if got.Status != policy.StatusActive {
		t.Errorf("Status = %q; want active", got.Status)
	}
	if got.EnforcementMode != policy.ModeDeny {
		t.Errorf("EnforcementMode = %q; want deny", got.EnforcementMode)
	}
	if len(got.Conditions) != 1 || got.Conditions[0].Field != "country" {
		t.Errorf("Conditions = %+v; want [country equals SG]", got.Conditions)
	}
}

func TestPolicyRepository_Get_MalformedConditionJSONFails(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{scan: func(dest ...any) error {
				*(dest[0].(*string)) = uuid.NewString()
				*(dest[1].(*string)) = ""
				*(dest[2].(*string)) = "name"
				*(dest[3].(*string)) = ""
				*(dest[4].(*string)) = "{not-json"
				*(dest[5].(*string)) = "permitted"
				*(dest[6].(*bool)) = true
				*(dest[7].(*int)) = 1
				*(dest[8].(*time.Time)) = time.Now()
				*(dest[9].(*time.Time)) = time.Now()
				return nil
			}}
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.Get(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error decoding bad condition JSON")
	}
}

// -----------------------------------------------------------------------------
// List
// -----------------------------------------------------------------------------

func TestPolicyRepository_List_EmptyFilter_ReturnsEmpty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewPolicyRepository(q)
	out, err := repo.List(context.Background(), policy.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty; got %d", len(out))
	}
}

func TestPolicyRepository_List_AppendsTenantClause(t *testing.T) {
	t.Parallel()
	var capturedSQL string
	q := &stubQuerier{
		queryFn: func(sql string, _ ...any) (pg.Rows, error) {
			capturedSQL = sql
			return &stubRows{}, nil
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.List(context.Background(), policy.ListFilter{
		TenantID: uuid.NewString(),
		Limit:    10,
		Offset:   5,
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !contains(capturedSQL, "tenant_id =") {
		t.Errorf("expected tenant_id filter; got %q", capturedSQL)
	}
	if !contains(capturedSQL, "LIMIT") {
		t.Errorf("expected LIMIT clause; got %q", capturedSQL)
	}
	if !contains(capturedSQL, "OFFSET") {
		t.Errorf("expected OFFSET clause; got %q", capturedSQL)
	}
}

func TestPolicyRepository_List_QueryErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.List(context.Background(), policy.ListFilter{})
	if err == nil {
		t.Fatal("expected error to surface")
	}
}

func TestPolicyRepository_List_ScanErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{{"x"}}, scanErr: errors.New("scan fail")}, nil
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.List(context.Background(), policy.ListFilter{})
	if err == nil {
		t.Fatal("expected scan error to surface")
	}
}

func TestPolicyRepository_List_IterErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{iterErr: errors.New("iter fail")}, nil
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.List(context.Background(), policy.ListFilter{})
	if err == nil {
		t.Fatal("expected iter error to surface")
	}
}

// -----------------------------------------------------------------------------
// FindApplicable
// -----------------------------------------------------------------------------

func TestPolicyRepository_FindApplicable_EmitsActiveFilter(t *testing.T) {
	t.Parallel()
	var capturedSQL string
	q := &stubQuerier{
		queryFn: func(sql string, _ ...any) (pg.Rows, error) {
			capturedSQL = sql
			return &stubRows{}, nil
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.FindApplicable(context.Background(), uuid.NewString())
	if err != nil {
		t.Fatalf("FindApplicable: %v", err)
	}
	if !contains(capturedSQL, "active = TRUE") {
		t.Errorf("expected active filter; got %q", capturedSQL)
	}
	// Global rules (tenant_id IS NULL) must also be returned.
	if !contains(capturedSQL, "tenant_id IS NULL") {
		t.Errorf("expected tenant_id IS NULL clause; got %q", capturedSQL)
	}
}

func TestPolicyRepository_FindApplicable_QueryErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("db down")
		},
	}
	repo := pg.NewPolicyRepository(q)
	_, err := repo.FindApplicable(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error to surface")
	}
}
