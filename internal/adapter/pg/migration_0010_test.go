// migration_0010_test.go — static invariants for the PENDING-gate migration
// (0010_hitl_decision_log_pending_gate). These assert the migration encodes the
// pending-gate model correctly WITHOUT a live DB (migrations are applied +
// verified against Cloud SQL in CI; this guards the SQL contract at unit level
// so a regression on the file is caught before the slow apply job).
package pg_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readMigration(t *testing.T, name string) string {
	t.Helper()
	// pg test package lives at internal/adapter/pg → migrations are 3 dirs up.
	path := filepath.Join("..", "..", "..", "migrations", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return string(b)
}

// migrationStatements strips `--` line comments so structural assertions match
// only executable SQL, not prose in the migration header.
func migrationStatements(sql string) string {
	var out []string
	for _, line := range strings.Split(sql, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// TestMigration0010_AddsPendingEnumValue asserts the verdict enum gains the
// pending sentinel (idempotently).
func TestMigration0010_AddsPendingEnumValue(t *testing.T) {
	t.Parallel()
	stmts := migrationStatements(readMigration(t, "0010_hitl_decision_log_pending_gate.up.sql"))
	if !strings.Contains(stmts, "ALTER TYPE hitl_decision_verdict ADD VALUE IF NOT EXISTS 'pending'") {
		t.Errorf("0010 up must ADD VALUE IF NOT EXISTS 'pending' to hitl_decision_verdict; got:\n%s", stmts)
	}
}

// TestMigration0010_MakesOperatorGcidNullable asserts the operator_gcid column
// is made nullable (a pending gate has no operator).
func TestMigration0010_MakesOperatorGcidNullable(t *testing.T) {
	t.Parallel()
	up := migrationStatements(readMigration(t, "0010_hitl_decision_log_pending_gate.up.sql"))
	norm := strings.Join(strings.Fields(up), " ")
	if !strings.Contains(norm, "ALTER COLUMN operator_gcid DROP NOT NULL") {
		t.Errorf("0010 up must DROP NOT NULL on operator_gcid; got:\n%s", up)
	}
}

// TestMigration0010_NoExplicitTransaction asserts the ALTER-TYPE-ADD-VALUE
// statement is NOT wrapped in an explicit transaction block — PostgreSQL
// forbids ALTER TYPE ... ADD VALUE inside a tx (the 2026-05-13 silent-failure
// lesson). The migration runner applies via `psql -f` without
// --single-transaction, so a bare file is correct.
func TestMigration0010_NoExplicitTransaction(t *testing.T) {
	t.Parallel()
	up := readMigration(t, "0010_hitl_decision_log_pending_gate.up.sql")
	stmts := strings.ToUpper(migrationStatements(up))
	if strings.Contains(stmts, "BEGIN;") || strings.Contains(stmts, "COMMIT;") {
		t.Errorf("0010 up MUST NOT use BEGIN;/COMMIT; — ALTER TYPE ADD VALUE cannot run in an explicit tx")
	}
}

// TestMigration0010_DownGuardsPendingRows asserts the down migration refuses to
// restore NOT NULL while pending (NULL-operator) rows exist, rather than
// silently back-filling a synthetic operator.
func TestMigration0010_DownGuardsPendingRows(t *testing.T) {
	t.Parallel()
	down := migrationStatements(readMigration(t, "0010_hitl_decision_log_pending_gate.down.sql"))
	if !strings.Contains(down, "operator_gcid IS NULL") {
		t.Errorf("0010 down must assert no NULL-operator rows before restoring NOT NULL; got:\n%s", down)
	}
	norm := strings.Join(strings.Fields(down), " ")
	if !strings.Contains(norm, "ALTER COLUMN operator_gcid SET NOT NULL") {
		t.Errorf("0010 down must restore operator_gcid SET NOT NULL; got:\n%s", down)
	}
}
