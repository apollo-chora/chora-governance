-- 0008_hitl_decision_log_assignee_gcid.down.sql
--
-- Reverse of 0008_hitl_decision_log_assignee_gcid.up.sql — drops the
-- `assignee_gcid` column + its partial indexes from `hitl_decision_log`.
--
-- Idempotent: `DROP INDEX IF EXISTS` + `DROP COLUMN IF EXISTS`. Note: any
-- per-row assignee claim history is destroyed on down-migration; this is
-- acceptable because the column is read-only metadata for the O+ queue UI
-- and is not load-bearing for the append-only audit trail (which keeps
-- `operator_gcid` as the canonical "who decided" provenance).

DROP INDEX IF EXISTS idx_hitl_decision_log_unassigned;
DROP INDEX IF EXISTS idx_hitl_decision_log_assignee;

ALTER TABLE hitl_decision_log
    DROP COLUMN IF EXISTS assignee_gcid;
