// helpers_tail_test.go — coverage tail for cmd/server's composition-root
// helpers that are unit-testable without real infra:
//
//   - bootstrapDBPool / bootstrapOutboxDB / bootstrapPubSubClient empty-env
//     branches (return nil — dev fallback)
//   - outboxWorkerID priority ladder
//   - sqlDBAdapter bridge (erroring driver covers the call path)
//   - loadRubricConfig candidate walk + parse paths
//   - bootstrapRubric success + fail-soft branches
//
// main() and the env-set bootstrap branches that end in log.Fatal are NOT
// exercised (they require real secrets / a reachable Postgres and would
// terminate the test process).
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

// choraFakeErr is a registered driver whose connections error on every
// operation — lets the sqlDBAdapter bridge be exercised without a real DB.
type choraFakeErr struct{}

func (choraFakeErr) Open(string) (driver.Conn, error) { return choraFakeErrConn{}, nil }

type choraFakeErrConn struct{}

func (choraFakeErrConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("prepare boom") }
func (choraFakeErrConn) Close() error                        { return nil }
func (choraFakeErrConn) Begin() (driver.Tx, error)           { return nil, errors.New("begin boom") }

func init() { sql.Register("chora_fake_err", choraFakeErr{}) }

func TestBootstrapDBPool_NoEnvFallsBackToNil(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "")
	t.Setenv("CHORA_DB_DSN_SECRET_ID", "")
	pool, shutdown := bootstrapDBPool(context.Background())
	if pool != nil || shutdown != nil {
		t.Errorf("pool=%v shutdown!=nil; want nil/nil", pool)
	}
}

func TestBootstrapOutboxDB_NoEnvFallsBackToNil(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_DSN", "")
	t.Setenv("CHORA_OUTBOX_DSN_SECRET_ID", "")
	db, shutdown := bootstrapOutboxDB(context.Background())
	if db != nil || shutdown != nil {
		t.Errorf("db=%v shutdown!=nil; want nil/nil", db)
	}
}

func TestBootstrapBus_NoURLFallsBackToNil(t *testing.T) {
	t.Setenv("NATS_URL", "")
	bus, shutdown := bootstrapBus(context.Background())
	if bus != nil || shutdown != nil {
		t.Errorf("bus=%v shutdown!=nil; want nil/nil", bus)
	}
}

func TestOutboxWorkerID_Ladder(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_WORKER_ID", "worker-42")
	t.Setenv("HOSTNAME", "")
	if got := outboxWorkerID(); got != "worker-42" {
		t.Errorf("env branch: got %q", got)
	}

	t.Setenv("CHORA_OUTBOX_WORKER_ID", "")
	t.Setenv("HOSTNAME", "pod-7-host")
	if got := outboxWorkerID(); got != "pod-7-host" {
		t.Errorf("hostname branch: got %q", got)
	}

	t.Setenv("CHORA_OUTBOX_WORKER_ID", "")
	t.Setenv("HOSTNAME", "")
	if got := outboxWorkerID(); got != "chora-governance-"+time.Now().UTC().Format("20060102150405") {
		t.Errorf("fallback branch: got %q", got)
	}
}

func TestSQLDBAdapter_ExecAndQueryErrors(t *testing.T) {
	// A registered-but-broken driver: pool opens fine, every operation errors.
	db, err := sql.Open("chora_fake_err", "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	a := sqlDBAdapter{db: db}
	if _, err := a.ExecContext(context.Background(), "SELECT 1"); err == nil {
		t.Error("ExecContext should error with the fake driver")
	}
	if _, err := a.QueryContext(context.Background(), "SELECT 1"); err == nil {
		t.Error("QueryContext should error with the fake driver")
	}
}

func writeRubricYAML(t *testing.T) string {
	t.Helper()
	yaml := `dimensions:
  accountability:
    items:
      - id: raci
        title: RACI Matrix
        evidence_source: doc
        derivation_mode: static
        static_status: PASS
      - id: audit
        title: Audit Trail
        evidence_source: cloud_trace
        derivation_mode: auto
        auto_query_key: audit_trail_coverage
`
	path := filepath.Join(t.TempDir(), "imda_rubric.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadRubricConfig_FromEnvPath(t *testing.T) {
	path := writeRubricYAML(t)
	t.Setenv("CHORA_IMDA_RUBRIC_PATH", path)
	cfg, err := loadRubricConfig()
	if err != nil {
		t.Fatalf("loadRubricConfig: %v", err)
	}
	if len(cfg.Dimensions) != 1 {
		t.Errorf("dimensions = %d; want 1", len(cfg.Dimensions))
	}
}

func TestLoadRubricConfig_NoCandidatesErrors(t *testing.T) {
	t.Setenv("CHORA_IMDA_RUBRIC_PATH", "")
	// Point CWD candidates nowhere: run in a temp dir (current dir has no
	// config/imda_rubric.yaml) and the ../../config path resolves relative to
	// cmd/server — which also has no such file in the temp CWD.
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldwd) }()
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	if _, err := loadRubricConfig(); err == nil {
		t.Error("loadRubricConfig should error when no candidate exists")
	}
	if err := os.Chdir(oldwd); err != nil {
		t.Fatalf("restore Chdir: %v", err)
	}
}

func TestBootstrapRubric_Success(t *testing.T) {
	path := writeRubricYAML(t)
	t.Setenv("CHORA_IMDA_RUBRIC_PATH", path)
	resolver, svc := bootstrapRubric(imda.NewInMemoryRepository(), evidence.NewInMemoryRepository())
	if resolver == nil || svc == nil {
		t.Fatalf("resolver=%v svc=%v; want non-nil", resolver, svc)
	}
}

func TestBootstrapRubric_FailSoftBranches(t *testing.T) {
	// config load failure → nil/nil (run from a temp CWD so no candidate
	// resolves to the real config/imda_rubric.yaml)
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Setenv("CHORA_IMDA_RUBRIC_PATH", "")
	resolver, svc := bootstrapRubric(imda.NewInMemoryRepository(), evidence.NewInMemoryRepository())
	if resolver != nil || svc != nil {
		t.Errorf("config-load-fail: resolver=%v svc=%v; want nil/nil", resolver, svc)
	}
	if err := os.Chdir(oldwd); err != nil {
		t.Fatalf("restore Chdir: %v", err)
	}

	// nil evidence repo → nil/nil
	path := writeRubricYAML(t)
	t.Setenv("CHORA_IMDA_RUBRIC_PATH", path)
	resolver, svc = bootstrapRubric(imda.NewInMemoryRepository(), nil)
	if resolver != nil || svc != nil {
		t.Errorf("nil evidence: resolver=%v svc=%v; want nil/nil", resolver, svc)
	}
}
