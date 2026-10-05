// bootstrap.go — production wiring helpers for chora-governance.
//
// Per `feedback_resilience_priority` + `secrets-and-env`: every production
// dependency is sourced from env vars. Local dev sees nil pools / nil bus
// clients so the server keeps the in-memory adapter fallback working out of
// the box.
//
// Environment contract:
//
//	CHORA_DB_DSN_SECRET_ID  — environment-backed secret name resolving to a
//	                          chora_governance DSN (app_rw role).
//	CHORA_DB_DSN            — direct DSN (dev override; takes priority).
//	CHORA_DB_PROJECT        — project label used for secret resolution.
//	                          Defaults to chora-local.
//	CHORA_DB_REWRITE_FROM_PORT — bypass PgBouncer until the sidecar lands.
//	CHORA_DB_REWRITE_TO_PORT
//	NATS_URL                — NATS JetStream broker URL for the event bus.
//	CHORA_OUTBOX_DSN        — Postgres DSN pointing at chora_governance
//	                          for the producer-side outbox dispatcher.
//	                          Empty = in-memory outbox store (dev mode).
//	CHORA_OUTBOX_WORKER_ID  — worker ID stamped onto deadletter rows;
//	                          defaults to HOSTNAME.
//	CHORA_SOURCE_PROJECT    — source_project envelope stamp (default
//	                          chora-489812).
package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/apollo-chora/chora-common/db"
	"github.com/apollo-chora/chora-common/eventbus"
	cgcsecrets "github.com/apollo-chora/chora-common/secrets"
)

func bootstrapDBPool(ctx context.Context) (*pgxpool.Pool, func()) {
	dsn := os.Getenv("CHORA_DB_DSN")
	secretID := os.Getenv("CHORA_DB_DSN_SECRET_ID")
	if dsn == "" && secretID == "" {
		log.Printf("governance: CHORA_DB_DSN / CHORA_DB_DSN_SECRET_ID unset — using in-memory repositories")
		return nil, nil
	}

	project := os.Getenv("CHORA_DB_PROJECT")
	if project == "" {
		project = "chora-489812"
	}

	var fetcher db.SecretFetcher
	var sclient *cgcsecrets.Client
	if secretID != "" && dsn == "" {
		c, err := cgcsecrets.NewClient(ctx, project)
		if err != nil {
			log.Fatalf("governance: secret manager init failed (env set, fail-loud): %v", err)
		}
		sclient = c
		fetcher = c
	}

	rewriteFrom, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_FROM_PORT"))
	rewriteTo, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_TO_PORT"))

	// Gate-7 fix: env-driven bootstrap context (default 30s). Under
	// concurrent multi-pod cold-start, connection-pooler + secret resolution
	// can exceed 30s. Set CHORA_BOOTSTRAP_TIMEOUT_SECONDS to tune.
	bootstrapSecs, _ := strconv.Atoi(os.Getenv("CHORA_BOOTSTRAP_TIMEOUT_SECONDS"))
	if bootstrapSecs <= 0 {
		bootstrapSecs = 30
	}
	bootstrapCtx, cancel := context.WithTimeout(ctx, time.Duration(bootstrapSecs)*time.Second)
	defer cancel()

	pool, err := db.Bootstrap(bootstrapCtx, db.BootstrapOptions{
		DSN:             dsn,
		SecretID:        secretID,
		SecretFetcher:   fetcher,
		RewriteFromPort: rewriteFrom,
		RewriteToPort:   rewriteTo,
		AppName:         serviceName + "@" + version,
		RuntimeParams:   governanceDBRuntimeParams(),
	})
	if err != nil {
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("governance: pgx pool bootstrap failed (env set, fail-loud — kubelet will CrashLoopBackOff): %v", err)
	}

	shutdown := func() {
		pool.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
	}
	return pool, shutdown
}

// bootstrapBus returns a NATS JetStream eventbus when NATS_URL is set,
// otherwise nil (the caller falls back to the in-memory bus). The returned
// closure is the shutdown hook; caller defers it.
//
// Environment contract:
//
//	NATS_URL — JetStream broker URL (e.g. nats://127.0.0.1:4222).
//	           Unset → nil bus (in-process fallback; NOT durable).
func bootstrapBus(ctx context.Context) (eventbus.Bus, func()) {
	url := strings.TrimSpace(os.Getenv("NATS_URL"))
	if url == "" {
		return nil, nil
	}
	bus, err := eventbus.NewJetStream(eventbus.JetStreamConfig{URL: url})
	if err != nil {
		log.Printf("governance: NATS JetStream init failed: %v — falling back to in-memory bus", err)
		return nil, nil
	}
	return bus, func() { _ = bus.Close() }
}

// consumerConfig is the shared durable-consumer tuning for every
// chora-governance subscriber: at-least-once with a 30s ack window, five
// delivery attempts, and the canonical _dlq.<subject> dead-letter routing.
//
// The dotted event bus subscription id is safe as Name — eventbus sanitises it
// to a NATS-legal durable name internally.
func consumerConfig(name, subject string) eventbus.ConsumerConfig {
	return eventbus.ConsumerConfig{
		Name:       name,
		Subject:    subject,
		MaxDeliver: 5,
		AckWait:    30 * time.Second,
		Backoff: []time.Duration{
			1 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second,
		},
		DLQSubject: eventbus.DLQSubject(subject),
	}
}

// bootstrapOutboxDB opens a *sql.DB connection to chora_governance
// backing the D6.2 producer-side outbox.
//
// Env contract (paydown 2026-05-13):
//
//	CHORA_OUTBOX_DSN_SECRET_ID — environment-backed secret name (production).
//	CHORA_OUTBOX_DSN           — direct DSN (dev override; takes precedence).
//
// Both empty → return nil/nil (dev fallback signal; main() then wires the
// in-memory outbox.InMemoryStore).
// Either set + resolution / open / ping error → log.Fatal per fail-loud
// directive so kubelet CrashLoopBackOffs and retries with backoff.
func bootstrapOutboxDB(ctx context.Context) (*sql.DB, func()) {
	dsn := os.Getenv("CHORA_OUTBOX_DSN")
	secretID := os.Getenv("CHORA_OUTBOX_DSN_SECRET_ID")
	if dsn == "" && secretID == "" {
		return nil, nil
	}

	var sclient *cgcsecrets.Client
	if dsn == "" {
		project := os.Getenv("CHORA_DB_PROJECT")
		if project == "" {
			project = "chora-489812"
		}
		c, err := cgcsecrets.NewClient(ctx, project)
		if err != nil {
			log.Fatalf("governance: outbox secret manager init failed (env set, fail-loud): %v", err)
		}
		sclient = c
		bootstrapSecs, _ := strconv.Atoi(os.Getenv("CHORA_BOOTSTRAP_TIMEOUT_SECONDS"))
		if bootstrapSecs <= 0 {
			bootstrapSecs = 30
		}
		resolveCtx, cancel := context.WithTimeout(ctx, time.Duration(bootstrapSecs)*time.Second)
		defer cancel()
		resolved, err := c.GetSecret(resolveCtx, secretID)
		if err != nil {
			_ = c.Close()
			log.Fatalf("governance: outbox secret fetch %q failed (env set, fail-loud): %v", secretID, err)
		}
		dsn = resolved
	}

	if rewriteFrom, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_FROM_PORT")); rewriteFrom != 0 {
		if rewriteTo, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_TO_PORT")); rewriteTo != 0 {
			rewritten, err := db.RewriteDSNPort(dsn, rewriteFrom, rewriteTo)
			if err != nil {
				if sclient != nil {
					_ = sclient.Close()
				}
				log.Fatalf("governance: outbox DSN port rewrite failed (env set, fail-loud): %v", err)
			}
			dsn = rewritten
		}
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		db, err = sql.Open("postgres", dsn)
	}
	if err != nil {
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("governance: outbox sql.Open failed (env set, fail-loud): %v", err)
	}
	if pingErr := db.PingContext(ctx); pingErr != nil {
		_ = db.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("governance: outbox db.Ping failed (env set, fail-loud): %v", pingErr)
	}
	return db, func() {
		_ = db.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
	}
}

// governanceDBRuntimeParams returns the per-connection Postgres GUCs that keep a
// DB write from hanging forever (fail-loud). Platform-wide rollout of the
// CHO-2005 fix (2026-07-04); mirrors chora-consumption's
// consumptionDBRuntimeParams. Set on every pooled connection via
// BootstrapOptions.RuntimeParams.
//
//   - lock_timeout=3s: a statement blocked on a row lock ERRORs ("canceling
//     statement due to lock timeout") instead of waiting indefinitely and
//     leaking the request goroutine — under the gateway's 6s per-call
//     timeout, so this service fails loud (500) before the gateway 504s.
//   - idle_in_transaction_session_timeout=60s: reaps a leaked open
//     transaction so its row locks release.
//
// No statement_timeout (owner steer): long read paths must not be capped.
func governanceDBRuntimeParams() map[string]string {
	return map[string]string{
		"lock_timeout":                        "3s",
		"idle_in_transaction_session_timeout": "60s",
	}
}
