-- 0009_hitl_decision_log_assignee_update.up.sql
--
-- Unblock the HITL self-claim endpoint shipped in N7 (commit 03e7fbc3 —
-- `POST /api/hitl/decisions/{id}/claim` + `/release`). The endpoint's pg
-- adapter emits `UPDATE hitl_decision_log SET assignee_gcid = $3::uuid
-- WHERE ...`, but migration 0003's `trg_hitl_decision_log_no_update`
-- trigger (function `enforce_evidence_append_only`) rejects EVERY UPDATE
-- on the table. Without this relaxation the endpoint is wired but
-- non-functional in production (the InMemoryRepository path works fine
-- for tests + dev mode, which is why N7's coverage gate passed).
--
-- Approach
-- --------
-- Replace the per-table trigger with a column-aware one. The new trigger
-- function `enforce_hitl_decision_log_assignee_only_update` permits an
-- UPDATE if and only if `assignee_gcid` is the SOLE column whose value
-- changes (per `IS DISTINCT FROM` — NULL-safe). Every other column
-- preserves the append-only invariant that Tier 3 D9 evidence requires.
--
-- The generic `enforce_evidence_append_only` function used by every
-- other evidence table is unchanged; this migration only swaps the
-- per-table trigger binding on `hitl_decision_log`.
--
-- DELETE still reject — `trg_hitl_decision_log_no_delete` (also from
-- 0003) stays intact. The append-only invariant covers DELETE
-- unconditionally.
--
-- Audit posture
-- -------------
-- Claim history is not append-only in the strict ledger sense, but the
-- `assignee_gcid` column ITSELF carries a "current responsible reviewer"
-- semantic, not a verdict event. Each verdict (the operator_gcid +
-- decision + decided_at trio) remains permanently append-only. The
-- mutable assignee_gcid models the pre-verdict claim state which is by
-- design ephemeral until a verdict freezes the row's operator side.
--
-- A future hardening (deferred to wave M12.+) is to project every
-- assignee transition into a separate `hitl_claim_event_log` append-only
-- table so the claim sequence can be replayed; the current single-cell
-- mutation is adequate for the O+ Human Oversight UI need.
--
-- Idempotency
-- -----------
-- DROP TRIGGER IF EXISTS + CREATE OR REPLACE FUNCTION + CREATE TRIGGER
-- can be re-applied without error if the migration is re-run on a
-- partially-migrated DB.

CREATE OR REPLACE FUNCTION enforce_hitl_decision_log_assignee_only_update()
RETURNS TRIGGER AS $$
BEGIN
    -- Permit UPDATE iff assignee_gcid is the ONLY column whose value
    -- changed. Every other column must equal its OLD value under NULL-
    -- safe IS NOT DISTINCT FROM. id is also covered (PKs never change).
    IF NEW.id              IS DISTINCT FROM OLD.id              OR
       NEW.event_id        IS DISTINCT FROM OLD.event_id        OR
       NEW.tenant_id       IS DISTINCT FROM OLD.tenant_id       OR
       NEW.decision_id     IS DISTINCT FROM OLD.decision_id     OR
       NEW.run_id          IS DISTINCT FROM OLD.run_id          OR
       NEW.operator_gcid   IS DISTINCT FROM OLD.operator_gcid   OR
       NEW.decision        IS DISTINCT FROM OLD.decision        OR
       NEW.autonomy_level  IS DISTINCT FROM OLD.autonomy_level  OR
       NEW.edit_payload    IS DISTINCT FROM OLD.edit_payload    OR
       NEW.lifecycle_stage IS DISTINCT FROM OLD.lifecycle_stage OR
       NEW.decided_at      IS DISTINCT FROM OLD.decided_at      THEN
        RAISE EXCEPTION
            'hitl_decision_log is append-only except for assignee_gcid; UPDATE rejected (non-assignee column changed)';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_hitl_decision_log_no_update ON hitl_decision_log;

CREATE TRIGGER trg_hitl_decision_log_assignee_only_update
    BEFORE UPDATE ON hitl_decision_log
    FOR EACH ROW EXECUTE FUNCTION enforce_hitl_decision_log_assignee_only_update();
