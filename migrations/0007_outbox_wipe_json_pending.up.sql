-- 0007_outbox_wipe_json_pending.up.sql
--
-- Outbox payload encoding migration (codebase-wide JSON→binary-protobuf fix #33).
--
-- Background
-- ----------
-- Pre-fix outbox rows on chora_governance.outbox_events held JSON-marshalled
-- payload bytes that the schema registry (BINARY encoding) rejects at
-- publish time with "Invalid binary proto message". The dispatcher retries
-- forever (MaxAttempts=5 then deadletter) and the row never publishes.
--
-- Fix
-- ---
-- internal/adapter/events/protomarshal now emits canonical binary protobuf
-- bytes for the 9 schema-attached chora.governance.* topics with flat protos
-- in chora-contracts/proto/events-flat/governance/:
--
--   * chora.governance.closure.saga_step_completed.v1
--   * chora.governance.closure.saga_failed.v1
--   * chora.governance.audit.recorded.v1
--   * chora.governance.policy.violation_detected.v1
--   * chora.governance.policy.published.v1
--   * chora.governance.policy.updated.v1
--   * chora.governance.policy.retired.v1
--   * chora.governance.imda.dimension_attested.v1
--   * chora.governance.imda.evidence_gathered.v1
--
-- New rows written after the fix carry binary bytes and publish cleanly.
-- This migration drains pre-fix JSON-payload rows out of the pending queue
-- so the dispatcher stops retrying them; rows that NEVER successfully
-- published (still 'pending') are safe to mark 'failed' — no downstream
-- subscriber ever saw them.
--
-- Replay strategy
-- ---------------
-- We mark-failed rather than translate-and-retry: the producer-side handlers
-- (closure subscriber publishCompleted / publishFailed, gatekeeper deny path,
-- policy + audit projectors) are idempotent on envelope.idempotency_key —
-- re-triggering the upstream flow will emit a fresh correctly-encoded outbox
-- row. Translating JSON-decoded fields back into the typed proto would be
-- more error-prone than re-emission. These topics carry audit + closure-saga
-- semantics, so the upstream re-emission is the safe path.
--
-- Idempotent: re-running is a no-op (the WHERE clause matches no rows after
-- the first pass).
UPDATE outbox_events
SET status          = 'failed',
    last_error      = 'codebase-wide outbox protobuf encoding fix #33 — pre-fix JSON-payload row drained',
    last_attempt_at = now()
WHERE status = 'pending'
  AND topic IN (
    'chora.governance.closure.saga_step_completed.v1',
    'chora.governance.closure.saga_failed.v1',
    'chora.governance.audit.recorded.v1',
    'chora.governance.policy.violation_detected.v1',
    'chora.governance.policy.published.v1',
    'chora.governance.policy.updated.v1',
    'chora.governance.policy.retired.v1',
    'chora.governance.imda.dimension_attested.v1',
    'chora.governance.imda.evidence_gathered.v1'
  );
