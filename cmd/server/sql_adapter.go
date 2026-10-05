// sql_adapter.go — bridges database/sql.DB to chora-governance/internal/adapter/outbox.SQLDB.
//
// The outbox PostgresStore declares a minimal SQLDB interface (Exec + Query)
// returning its own SQLRows shape so the package can be tested without pulling
// in a real driver. This bridge wraps *sql.DB and returns *sql.Rows wrapped as
// outbox.SQLRows.
package main

import (
	"context"
	"database/sql"
	"os"
	"time"

	"github.com/apollo-chora/chora-governance/internal/adapter/outbox"
)

// sqlDBAdapter wraps *sql.DB so the outbox.SQLDB interface is satisfied.
type sqlDBAdapter struct {
	db *sql.DB
}

func (a sqlDBAdapter) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return a.db.ExecContext(ctx, q, args...)
}

func (a sqlDBAdapter) QueryContext(ctx context.Context, q string, args ...any) (outbox.SQLRows, error) {
	rows, err := a.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// outboxWorkerID returns the worker ID stamped onto deadletter rows. Derived
// from CHORA_OUTBOX_WORKER_ID, then HOSTNAME, then a deterministic
// service-instance default. The dispatcher requires a non-empty worker_id at
// construction time.
func outboxWorkerID() string {
	if v := os.Getenv("CHORA_OUTBOX_WORKER_ID"); v != "" {
		return v
	}
	if v := os.Getenv("HOSTNAME"); v != "" {
		return v
	}
	// stable fallback — ensure dispatcher does not panic in unit-tests / local
	// dev runs where neither HOSTNAME nor CHORA_OUTBOX_WORKER_ID is set.
	return "chora-governance-" + time.Now().UTC().Format("20060102150405")
}
