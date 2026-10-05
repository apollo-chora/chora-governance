-- 0010_hitl_decision_log_pending_gate.up.sql
--
-- Adds the PENDING-gate enqueue path to hitl_decision_log so the O+ Human-
-- Oversight queue (/api/hitl/pending) can receive a HITL gate the moment a
-- qgen quality-gate escalation fires — BEFORE any operator has decided it.
--
-- Background
-- ----------
-- chora-ai-kernel-orchestrator (qgen crew, commit a977a483) emits
-- `chora.governance.hitl.requested.v1` when a quality gate exhausts retries
-- with a warning. The chora-governance projector (routeD4 → AppendHITLDecision)
-- now enqueues that as a PENDING row. But the original schema (migration 0003)
-- only modelled RESOLVED decisions:
--
--   * `hitl_decision_verdict` enum = {approve, reject, edit} — no "pending".
--   * `operator_gcid` was NOT NULL — but a pending gate has no operator yet.
--
-- This migration relaxes both, backward-compatibly. RESOLVED rows are
-- unaffected: a real verdict still carries a canonical value + operator_gcid.
-- The verdict columns stay append-only (migration 0009 trigger) — a pending
-- gate is RESOLVED by APPENDING a fresh row sharing (tenant_id, decision_id,
-- run_id) with a real verdict + operator, NOT by updating the pending row in
-- place.
--
-- The pending-gate model (enum/nullable/lifecycle) is documented in the
-- session handoff; flagged as potentially ADR-worthy (the HitlVerdict enum now
-- carries a pre-verdict sentinel — a deliberate domain modelling choice).
--
-- TRANSACTIONALITY
--   `ALTER TYPE ... ADD VALUE` CANNOT run inside an explicit transaction block
--   (PostgreSQL restriction; surfaced as the 2026-05-13 ALTER-TYPE-in-tx silent
--   failure noted in chora-infra/scripts/migrations-runner/runner.sh:44). This
--   file therefore runs each statement at TOP LEVEL — NO `BEGIN;`/`COMMIT;`.
--   The migration runner applies the file with `psql -f` (no
--   --single-transaction), so each statement commits in its own implicit
--   transaction. The `ALTER COLUMN ... DROP NOT NULL` does NOT reference the new
--   enum value, so it is safe in a separate implicit transaction even though
--   the new value is not yet usable in the same tx it was added.
--
-- IDEMPOTENCY
--   * `ADD VALUE IF NOT EXISTS 'pending'` (PostgreSQL >= 12) — re-runnable.
--   * `DROP NOT NULL` is naturally idempotent (already-nullable → no-op).

-- 1. Add the pending sentinel to the verdict enum. IF NOT EXISTS guards re-run.
ALTER TYPE hitl_decision_verdict ADD VALUE IF NOT EXISTS 'pending';

-- 2. Make operator_gcid nullable — a PENDING gate carries no operator until a
--    reviewer records a verdict (on a fresh appended row).
ALTER TABLE hitl_decision_log
    ALTER COLUMN operator_gcid DROP NOT NULL;

COMMENT ON COLUMN hitl_decision_log.operator_gcid IS
    'Auditor who DECIDED the gate (recorded a verdict). NULL on a PENDING gate (migration 0010) — a pending escalation has no operator until a reviewer resolves it by APPENDING a verdict row. Distinct from assignee_gcid (who is currently RESPONSIBLE).';
