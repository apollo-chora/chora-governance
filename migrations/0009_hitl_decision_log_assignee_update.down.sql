-- 0009_hitl_decision_log_assignee_update.down.sql
--
-- Restore the original migration-0003 binding: every UPDATE on
-- hitl_decision_log goes through the generic
-- `enforce_evidence_append_only` rejection function.
--
-- WARNING: rolling this back makes the N7 HITL claim endpoint
-- non-functional in production again (the InMemoryRepository path still
-- works for tests + dev mode). Any rows where `assignee_gcid` is
-- non-NULL stay at their current value — the down migration does NOT
-- clear claim state.

DROP TRIGGER IF EXISTS trg_hitl_decision_log_assignee_only_update
    ON hitl_decision_log;

DROP FUNCTION IF EXISTS enforce_hitl_decision_log_assignee_only_update();

CREATE TRIGGER trg_hitl_decision_log_no_update
    BEFORE UPDATE ON hitl_decision_log
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
