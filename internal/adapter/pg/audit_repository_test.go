// audit_repository_test.go — pgx adapter tests using a stub Querier.
package pg_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

// -----------------------------------------------------------------------------
// stub Querier (multi-mode: Exec + QueryRow + Query)
// -----------------------------------------------------------------------------

type stubQuerier struct {
	execSQL    string
	execArgs   []any
	execErr    error
	queryRowFn func(sql string, args ...any) pg.Row
	queryFn    func(sql string, args ...any) (pg.Rows, error)

	// txCalled + txTenantID capture the most recent WithTenantTx invocation
	// (the value the repo would inject via `SET LOCAL chora.tenant_id`). Used
	// by the evidence-repository RLS-scoping tests to assert the GUC matches
	// the row's tenant. The base Querier surface (audit / imda / policy repos)
	// never calls WithTenantTx, so these stay zero-valued there.
	txCalled   bool
	txTenantID string
}

func (s *stubQuerier) Exec(_ context.Context, sql string, args ...any) error {
	s.execSQL = sql
	s.execArgs = args
	return s.execErr
}

func (s *stubQuerier) QueryRow(_ context.Context, sql string, args ...any) pg.Row {
	if s.queryRowFn != nil {
		return s.queryRowFn(sql, args...)
	}
	return &stubRow{err: pg.ErrNoRows}
}

func (s *stubQuerier) Query(_ context.Context, sql string, args ...any) (pg.Rows, error) {
	if s.queryFn != nil {
		return s.queryFn(sql, args...)
	}
	return &stubRows{}, nil
}

// WithTenantTx records the tenant_id the repo would apply via
// `SET LOCAL chora.tenant_id` and delegates fn to the stub itself so the
// Exec/Query/QueryRow capture still works inside the callback. Mirrors the
// chora-observability ledger/decision test double.
func (s *stubQuerier) WithTenantTx(ctx context.Context, tenantID string, fn func(context.Context, pg.TenantScopedQuerier) error) error {
	s.txCalled = true
	s.txTenantID = tenantID
	return fn(ctx, s)
}

type stubRow struct {
	scan func(dest ...any) error
	err  error
}

func (r *stubRow) Scan(dest ...any) error {
	if r.scan != nil {
		return r.scan(dest...)
	}
	return r.err
}

type stubRows struct {
	rows    [][]any
	pos     int
	closed  bool
	scanErr error
	iterErr error
}

func (r *stubRows) Next() bool {
	r.pos++
	return r.pos <= len(r.rows)
}

func (r *stubRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	row := r.rows[r.pos-1]
	for i, d := range dest {
		switch dp := d.(type) {
		case *string:
			*dp = row[i].(string)
		case *time.Time:
			*dp = row[i].(time.Time)
		case *bool:
			*dp = row[i].(bool)
		case *int:
			*dp = row[i].(int)
		case *int64:
			*dp = row[i].(int64)
		case *float64:
			*dp = row[i].(float64)
		case **time.Time:
			if row[i] == nil {
				*dp = nil
				continue
			}
			switch tv := row[i].(type) {
			case time.Time:
				v := tv
				*dp = &v
			case *time.Time:
				if tv == nil {
					*dp = nil
				} else {
					v := *tv
					*dp = &v
				}
			default:
				*dp = nil
			}
		case *sql.NullString:
			// Nullable-string column support — N7 self-claim wave adds
			// assignee_gcid NULL on hitl_decision_log. nil in row = SQL NULL;
			// non-nil string = Valid=true.
			if row[i] == nil {
				*dp = sql.NullString{}
				continue
			}
			switch sv := row[i].(type) {
			case string:
				*dp = sql.NullString{String: sv, Valid: true}
			case sql.NullString:
				*dp = sv
			default:
				*dp = sql.NullString{}
			}
		}
	}
	return nil
}

func (r *stubRows) Close()     { r.closed = true }
func (r *stubRows) Err() error { return r.iterErr }

// -----------------------------------------------------------------------------
// Append
// -----------------------------------------------------------------------------

func newEvent(t *testing.T) *audit.Event {
	t.Helper()
	tenant := uuid.NewString()
	gcid := uuid.NewString()
	e, err := audit.New(audit.NewParams{
		TenantID:  tenant,
		Gcid:      gcid,
		Action:    "gatekeeper.deny",
		Resource:  "atom-publish",
		Decision:  audit.DecisionDenied,
		Reason:    "policy mismatch",
		ActorGcid: gcid,
	})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	return e
}

func TestAuditRepository_Append_FirstEvent_EmitsInsertWithGenesisPrevHash(t *testing.T) {
	t.Parallel()
	e := newEvent(t)
	q := &stubQuerier{
		// head lookup returns ErrNoRows (no prior chain)
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: pg.ErrNoRows}
		},
	}
	repo := pg.NewAuditRepository(q)
	if err := repo.Append(context.Background(), e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e.PrevHash != "" {
		t.Errorf("expected genesis PrevHash=''; got %q", e.PrevHash)
	}
	if e.EntryHash == "" {
		t.Errorf("expected EntryHash to be computed")
	}
	if !contains(q.execSQL, "INSERT INTO audit_log") {
		t.Errorf("expected INSERT INTO audit_log; got %q", q.execSQL)
	}
}

func TestAuditRepository_Append_ChainsOnPriorHead(t *testing.T) {
	t.Parallel()
	e := newEvent(t)
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{scan: func(dest ...any) error {
				*(dest[0].(*string)) = "prev-hash-xyz"
				return nil
			}}
		},
	}
	repo := pg.NewAuditRepository(q)
	if err := repo.Append(context.Background(), e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e.PrevHash != "prev-hash-xyz" {
		t.Errorf("PrevHash = %q; want prev-hash-xyz", e.PrevHash)
	}
}

func TestAuditRepository_Append_DuplicateMaps_ErrAlreadyExists(t *testing.T) {
	t.Parallel()
	e := newEvent(t)
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: pg.ErrNoRows}
		},
		execErr: errors.New("ERROR: duplicate key value violates unique constraint \"audit_log_pkey\" (SQLSTATE 23505)"),
	}
	repo := pg.NewAuditRepository(q)
	err := repo.Append(context.Background(), e)
	if !errors.Is(err, audit.ErrAlreadyExists) {
		t.Errorf("err = %v; want audit.ErrAlreadyExists", err)
	}
}

func TestAuditRepository_Append_HeadLookupErrorSurfaces(t *testing.T) {
	t.Parallel()
	e := newEvent(t)
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: errors.New("connection refused")}
		},
	}
	repo := pg.NewAuditRepository(q)
	err := repo.Append(context.Background(), e)
	if err == nil {
		t.Fatal("expected error from head lookup failure")
	}
}

// -----------------------------------------------------------------------------
// GetByID
// -----------------------------------------------------------------------------

func TestAuditRepository_GetByID_NotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: pg.ErrNoRows}
		},
	}
	repo := pg.NewAuditRepository(q)
	_, err := repo.GetByID(context.Background(), "00000000-0000-7000-9000-000000000001")
	if !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("err = %v; want audit.ErrNotFound", err)
	}
}

func TestAuditRepository_GetByID_OtherErrorWraps(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: errors.New("query failed")}
		},
	}
	repo := pg.NewAuditRepository(q)
	_, err := repo.GetByID(context.Background(), "x")
	if err == nil || errors.Is(err, audit.ErrNotFound) {
		t.Errorf("expected wrapped non-ErrNotFound error; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Query (filter building + result scanning)
// -----------------------------------------------------------------------------

func TestAuditRepository_Query_EmptyFilter_ReturnsEmpty(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewAuditRepository(q)
	out, err := repo.Query(context.Background(), audit.QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty result; got %d", len(out))
	}
}

func TestAuditRepository_Query_AppendsFilterClauses(t *testing.T) {
	t.Parallel()
	from := time.Now().Add(-1 * time.Hour)
	to := time.Now()
	var capturedSQL string
	var capturedArgs []any
	q := &stubQuerier{
		queryFn: func(sql string, args ...any) (pg.Rows, error) {
			capturedSQL = sql
			capturedArgs = args
			return &stubRows{}, nil
		},
	}
	repo := pg.NewAuditRepository(q)
	_, err := repo.Query(context.Background(), audit.QueryFilter{
		TenantID:    "tenant-1",
		SubjectID:   "subj-1",
		SubjectType: "atom",
		From:        &from,
		To:          &to,
		Limit:       50,
		Offset:      10,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// Verify each filter is appended.
	for _, frag := range []string{
		"tenant_id = $1::uuid",
		"subject_id = $2",
		"subject_type = $3",
		"created_at >= $4",
		"created_at <= $5",
		"LIMIT $6",
		"OFFSET $7",
		"ORDER BY created_at ASC",
	} {
		if !contains(capturedSQL, frag) {
			t.Errorf("expected SQL to contain %q; got:\n%s", frag, capturedSQL)
		}
	}
	if len(capturedArgs) != 7 {
		t.Errorf("expected 7 args; got %d", len(capturedArgs))
	}
}

func TestAuditRepository_Query_ScanErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{rows: [][]any{{"x"}}, scanErr: errors.New("scan fail")}, nil
		},
	}
	repo := pg.NewAuditRepository(q)
	_, err := repo.Query(context.Background(), audit.QueryFilter{})
	if err == nil {
		t.Fatal("expected scan error to surface")
	}
}

func TestAuditRepository_Query_IterErrorSurfaces(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{iterErr: errors.New("iter fail")}, nil
		},
	}
	repo := pg.NewAuditRepository(q)
	_, err := repo.Query(context.Background(), audit.QueryFilter{})
	if err == nil {
		t.Fatal("expected iter error to surface")
	}
}

func TestAuditRepository_VerifyEntry_TamperedReturnsFalse(t *testing.T) {
	t.Parallel()
	e := newEvent(t)
	e.PrevHash = ""
	e.EntryHash = "bogus-hash"
	now := time.Now().UTC()
	e.CreatedAt = now
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{scan: func(dest ...any) error {
				*(dest[0].(*string)) = e.EventID
				*(dest[1].(*string)) = e.TenantID
				*(dest[2].(*string)) = e.Gcid
				*(dest[3].(*string)) = ""
				*(dest[4].(*string)) = e.Action
				*(dest[5].(*string)) = e.Resource
				*(dest[6].(*string)) = string(e.Decision)
				*(dest[7].(*string)) = e.Reason
				*(dest[8].(*string)) = ""
				*(dest[9].(*string)) = ""
				*(dest[10].(*string)) = e.ActorGcid
				*(dest[11].(*string)) = ""
				*(dest[12].(*string)) = ""
				*(dest[13].(*string)) = ""
				*(dest[14].(*string)) = ""
				*(dest[15].(*string)) = e.PrevHash
				*(dest[16].(*string)) = e.EntryHash
				*(dest[17].(*time.Time)) = now
				return nil
			}}
		},
	}
	repo := pg.NewAuditRepository(q)
	ok, err := repo.VerifyEntry(context.Background(), e.EventID)
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
	if ok {
		t.Errorf("tampered hash should return false")
	}
}

func TestAuditRepository_VerifyEntry_NotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: pg.ErrNoRows}
		},
	}
	repo := pg.NewAuditRepository(q)
	_, err := repo.VerifyEntry(context.Background(), "x")
	if !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("err = %v; want audit.ErrNotFound", err)
	}
}

func TestAuditRepository_Query_ErrorPropagates(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return nil, errors.New("connection failed")
		},
	}
	repo := pg.NewAuditRepository(q)
	_, err := repo.Query(context.Background(), audit.QueryFilter{TenantID: "t1"})
	if err == nil {
		t.Fatal("expected error to surface")
	}
}

// -----------------------------------------------------------------------------
// VerifyChain — empty chain is valid
// -----------------------------------------------------------------------------

func TestAuditRepository_VerifyChain_EmptyChainValid(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		queryFn: func(_ string, _ ...any) (pg.Rows, error) {
			return &stubRows{}, nil
		},
	}
	repo := pg.NewAuditRepository(q)
	r, err := repo.VerifyChain(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !r.Valid {
		t.Errorf("empty chain should be Valid=true; got %+v", r)
	}
	if r.Verified != 0 {
		t.Errorf("Verified = %d; want 0", r.Verified)
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
