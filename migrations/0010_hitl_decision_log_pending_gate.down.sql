-- 0010_hitl_decision_log_pending_gate.down.sql
--
-- Reverts the operator_gcid nullability relaxation. The enum value 'pending'
-- is NOT removed — see WARNING.
--
-- operator_gcid NOT NULL restoration
-- ----------------------------------
-- Restoring NOT NULL FAILS if any PENDING rows remain (their operator_gcid is
-- NULL). The down migration first asserts none remain; if pending rows exist
-- the rollback aborts loudly (operator must resolve or purge them first — a
-- pending gate with no operator is, by definition, not-yet-decided and cannot
-- be silently back-filled with a synthetic operator per
-- [[feedback-no-stubs-real-wiring]]).
--
-- WARNING — enum value 'pending' is irreversible here
-- ---------------------------------------------------
-- PostgreSQL has NO `ALTER TYPE ... DROP VALUE`. Removing 'pending' from
-- hitl_decision_verdict would require the full rename-type / recreate-type /
-- rewrite-column / drop-old-type dance against a live append-only,
-- RLS-protected, trigger-guarded table — disproportionate + risky for a
-- rollback. The extra enum value is harmless when unused (no row references it
-- once pending gates are resolved). It is therefore left in place; only the
-- NOT NULL constraint is restored. Re-applying 0010 up is a no-op
-- (ADD VALUE IF NOT EXISTS + already-nullable DROP NOT NULL).

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM hitl_decision_log WHERE operator_gcid IS NULL
    ) THEN
        RAISE EXCEPTION
            'cannot restore operator_gcid NOT NULL: PENDING rows with NULL operator_gcid exist — resolve or purge them before rolling back 0010';
    END IF;
END
$$;

ALTER TABLE hitl_decision_log
    ALTER COLUMN operator_gcid SET NOT NULL;

COMMENT ON COLUMN hitl_decision_log.operator_gcid IS
    'GCID of the auditor who DECIDED the gate. Distinct from assignee_gcid (who is currently RESPONSIBLE).';
