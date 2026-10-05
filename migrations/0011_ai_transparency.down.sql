-- =============================================================================
-- chora-governance : 0011_ai_transparency.down.sql  (rollback of 0011 up)
-- =============================================================================

BEGIN;

DROP TRIGGER IF EXISTS trg_ai_transparency_ack_no_update ON ai_transparency_acknowledgement;
DROP TRIGGER IF EXISTS trg_ai_transparency_ack_no_delete ON ai_transparency_acknowledgement;

DROP TABLE IF EXISTS ai_transparency_acknowledgement;
DROP TABLE IF EXISTS transparency_disclosure_version;

DROP TYPE IF EXISTS disclosure_status;

COMMIT;
