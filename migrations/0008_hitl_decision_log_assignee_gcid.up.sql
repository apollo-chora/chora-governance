-- 0008_hitl_decision_log_assignee_gcid.up.sql
--
-- Adds the `assignee_gcid` column to `hitl_decision_log` so the O+ Human
-- Oversight tab can render who (if anyone) is currently responsible for a
-- pending HITL gate. This unblocks the schema-reconciliation TODO(M12) marker
-- introduced by commit `60066c05` (BFF `mapHITLItem` had been emitting `""` as
-- a placeholder).
--
-- Semantics — self-claimed model
-- ------------------------------
-- The schema previously tracked ONLY `operator_gcid` which is the auditor who
-- DECIDED (recorded a verdict on) a gate. That is structurally distinct from
-- the reviewer currently RESPONSIBLE for a pending gate. `assignee_gcid` fills
-- that second slot.
--
-- For now, no pre-assignment routing service exists, so:
--   * Default at creation = NULL  → "unassigned" — sits in shared queue.
--   * Set to a reviewer GCID when that reviewer claims the gate via the
--     (deferred to wave N+1) `POST /api/hitl/decisions/{id}/claim` endpoint.
--   * Once a verdict is recorded `operator_gcid` is filled; `assignee_gcid`
--     is left as-is (it carries claim history; it is NOT overwritten with
--     `operator_gcid` at verdict time).
--
-- Nullable on purpose — `NULL` is the honest "no one is reviewing this yet"
-- semantic, per [[feedback-no-stubs-real-wiring]]. No synthetic placeholder
-- value is ever written.
--
-- Index
-- -----
-- A partial index on `WHERE assignee_gcid IS NULL` keeps the unassigned-queue
-- filter cheap as the table grows. Composite with `tenant_id` so the O+
-- per-tenant scoped query stays sargable.
--
-- Idempotent: `ADD COLUMN IF NOT EXISTS` + `CREATE INDEX IF NOT EXISTS`.

ALTER TABLE hitl_decision_log
    ADD COLUMN IF NOT EXISTS assignee_gcid UUID NULL;

COMMENT ON COLUMN hitl_decision_log.assignee_gcid IS
    'Reviewer GCID currently responsible for the gate. NULL = unassigned (default at creation). Distinct from operator_gcid (who DECIDED). Set when a reviewer claims the gate via POST /api/hitl/decisions/{id}/claim (wave N+1). NEVER backfilled with operator_gcid at verdict time.';

CREATE INDEX IF NOT EXISTS idx_hitl_decision_log_unassigned
    ON hitl_decision_log (tenant_id, decided_at DESC)
    WHERE assignee_gcid IS NULL;

CREATE INDEX IF NOT EXISTS idx_hitl_decision_log_assignee
    ON hitl_decision_log (assignee_gcid)
    WHERE assignee_gcid IS NOT NULL;
