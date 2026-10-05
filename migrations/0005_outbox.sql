-- =============================================================================
-- chora-governance : 0005_outbox.sql
--
-- Adds the transactional outbox primitive to chora_governance per the
-- M12.3 Wave-2 D6.2 producer-side durability uplift (`feedback_d6_resilience_first_class`
-- + `agentic-resilience-d6` skill Pillar 2) and Phase 5 (Phase 4-10 plan
-- 2026-05-13) full canonical bring-up. Mirrors chora-tenancy 0005_outbox.sql.
--
-- Domain  : Governance (supporting/platform; IMDA + compliance + audit)
-- Database: chora_governance
-- Date    : 2026-05-13 (Phase 5.A.1)
--
-- HARD INVARIANT: outbox rows live in the SAME database as the domain
-- they serve (chora_governance). Cross-DB queries forbidden — the
-- background Dispatcher publishes to Cloud Pub/Sub topic
-- `chora.governance.policy.violation_detected.v1` (and family) and
-- downstream subscribers consume via Pub/Sub.
--
-- D6.2 columns:
--   - tenant_id (UUID, NOT NULL) — IMDA D1 accountability requires
--     per-tenant attribution on every governance event.
--   - gcid (UUID, nullable) — subject (closure / training-data ban / etc.).
--   - idempotency_key UNIQUE — producer-side dedupe.
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS outbox_events (
    id              TEXT        PRIMARY KEY,
    tenant_id       UUID        NOT NULL,                    -- D6.3 isolation + IMDA D1
    gcid            UUID,                                    -- subject (nullable for system events)
    aggregate_type  TEXT        NOT NULL,
    aggregate_id    TEXT        NOT NULL,
    event_type      TEXT        NOT NULL,
    topic           TEXT        NOT NULL,
    payload         BYTEA       NOT NULL,
    envelope        JSONB       NOT NULL,
    idempotency_key TEXT        NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','published','failed','deadlettered')),
    retry_count     INT         NOT NULL DEFAULT 0,
    last_error      TEXT        NOT NULL DEFAULT '',
    last_attempt_at TIMESTAMPTZ,
    published_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dispatcher poll query — find next pending event by occurred_at.
CREATE INDEX IF NOT EXISTS outbox_events_pending_idx
    ON outbox_events (occurred_at ASC) WHERE status = 'pending';

-- D6.3 multi-tenant isolation lookup.
CREATE INDEX IF NOT EXISTS outbox_events_tenant_idx
    ON outbox_events (tenant_id, status, occurred_at);

-- Per-aggregate read.
CREATE INDEX IF NOT EXISTS outbox_events_aggregate_idx
    ON outbox_events (aggregate_type, aggregate_id, occurred_at DESC);

-- Per-topic dispatcher worker mode.
CREATE INDEX IF NOT EXISTS outbox_events_topic_idx
    ON outbox_events (topic, status);

-- Idempotency dedupe.
CREATE UNIQUE INDEX IF NOT EXISTS outbox_events_idempotency_idx
    ON outbox_events (idempotency_key);

CREATE TABLE IF NOT EXISTS outbox_poll_checkpoints (
    worker_id                  TEXT        NOT NULL,
    topic                      TEXT        NOT NULL,
    last_processed_outbox_id   TEXT        NOT NULL,
    last_processed_occurred_at TIMESTAMPTZ NOT NULL,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (worker_id, topic)
);

CREATE INDEX IF NOT EXISTS outbox_poll_checkpoints_topic_idx
    ON outbox_poll_checkpoints (topic, updated_at DESC);

CREATE TABLE IF NOT EXISTS outbox_dead_letters (
    outbox_event_id   TEXT        PRIMARY KEY REFERENCES outbox_events(id),
    failure_reason    TEXT        NOT NULL,
    attempt_count     INT         NOT NULL,
    worker_id         TEXT        NOT NULL,
    deadlettered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at       TIMESTAMPTZ,
    resolution_note   TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS outbox_dead_letters_unresolved_idx
    ON outbox_dead_letters (deadlettered_at DESC) WHERE resolved_at IS NULL;

-- ----------------------------------------------------------------------------
-- D6.3 RLS — multi-tenant isolation indexed on tenant_id.
-- ----------------------------------------------------------------------------
ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS outbox_events_tenant_isolation ON outbox_events;
CREATE POLICY outbox_events_tenant_isolation ON outbox_events
    USING (
        current_setting('app.current_tenant', TRUE) IS NULL
        OR current_setting('app.current_tenant', TRUE) = ''
        OR tenant_id::TEXT = current_setting('app.current_tenant', TRUE)
    );

COMMIT;
