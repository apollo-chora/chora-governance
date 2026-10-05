-- =============================================================================
-- chora-governance : 0001_initial.sql
--
-- Domain        : Governance (supporting/platform)
-- Database      : chora_governance
-- Author        : agent-a5e52e89b73ede1d2 (db-migrations-11-services)
-- Date          : 2026-05-08
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 5 D18) — IMDA NorthStar
--
-- Aggregates owned by this database:
--   - audit_log (APPEND-ONLY tamper-evident hash chain per tenant)
--   - pii_closure_maps (per-domain YAML registry for federated closure saga)
--   - imda_dimension_aggregates (IMDA 4-dimension report aggregates)
--   - imda_assessments (per-dimension scores + indicators)
--
-- All audit + IMDA tables are APPEND-ONLY: UPDATE / DELETE rejected by trigger.
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE OR REPLACE FUNCTION governance_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- -----------------------------------------------------------------------------
-- ENUMs
-- -----------------------------------------------------------------------------
CREATE TYPE audit_decision        AS ENUM ('permitted', 'denied');
CREATE TYPE imda_dimension        AS ENUM (
    'risk_levels',                  -- D1
    'operations_management',        -- D2
    'internal_governance',          -- D3
    'stakeholder_interaction'       -- D4
);

-- -----------------------------------------------------------------------------
-- audit_log — APPEND-ONLY tamper-evident hash chain
--
-- Each entry's entry_hash = SHA-256(canonical(entry) || prev_hash).
-- prev_hash points at the previous entry on the per-tenant chain.
-- Hash + prev_hash + traceparent enable tamper detection + Cloud Trace correlation.
-- -----------------------------------------------------------------------------
CREATE TABLE audit_log (
    event_id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID            NOT NULL,
    gcid              UUID            NOT NULL,                     -- subject GCID
    agid              UUID            NULL,                         -- nullable: AGID actor
    action            VARCHAR(128)    NOT NULL,
    resource          VARCHAR(256)    NOT NULL DEFAULT '',
    decision          audit_decision  NOT NULL,
    reason            TEXT            NOT NULL DEFAULT '',
    subject_type      VARCHAR(64)     NOT NULL DEFAULT '',
    subject_id        VARCHAR(128)    NOT NULL DEFAULT '',
    actor_gcid        UUID            NOT NULL,
    before_state      JSONB           NULL,
    after_state       JSONB           NULL,
    traceparent       VARCHAR(64)     NULL,
    tracestate        TEXT            NULL,
    prev_hash         CHAR(64)        NOT NULL DEFAULT '',           -- empty = genesis
    entry_hash        CHAR(64)        NOT NULL,
    occurred_at       TIMESTAMPTZ     NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_tenant     ON audit_log (tenant_id, created_at DESC);
CREATE INDEX idx_audit_log_gcid       ON audit_log (gcid);
CREATE INDEX idx_audit_log_agid       ON audit_log (agid) WHERE agid IS NOT NULL;
CREATE INDEX idx_audit_log_action     ON audit_log (action);
CREATE INDEX idx_audit_log_subject    ON audit_log (subject_type, subject_id);
CREATE INDEX idx_audit_log_decision   ON audit_log (decision);
CREATE INDEX idx_audit_log_traceparent ON audit_log (traceparent) WHERE traceparent IS NOT NULL;

CREATE OR REPLACE FUNCTION enforce_audit_log_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (governance invariant): % rejected', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION enforce_audit_log_append_only();

CREATE TRIGGER trg_audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION enforce_audit_log_append_only();

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_log
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- pii_closure_maps — per-domain YAML closure registry (one row per domain)
--
-- Per Tier 3 D11 + ddd-enforcement Account Closure: each domain owns its own
-- PII_Closure_Map.yaml declaring fields-to-tokenize, retention rules, and
-- on-creator-closure behaviour. The closure orchestrator reads this registry
-- to drive federated saga steps.
-- -----------------------------------------------------------------------------
CREATE TABLE pii_closure_maps (
    domain               VARCHAR(64)   PRIMARY KEY,                 -- creation/consumption/...
    yaml_content         TEXT          NOT NULL,
    yaml_hash            CHAR(64)      NOT NULL,                    -- SHA-256 of yaml_content
    version              INTEGER       NOT NULL DEFAULT 1,
    registered_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_pii_closure_maps_updated_at
    BEFORE UPDATE ON pii_closure_maps
    FOR EACH ROW EXECUTE FUNCTION governance_set_updated_at();

-- pii_closure_maps is platform-global (not tenant-scoped) — no RLS.

-- -----------------------------------------------------------------------------
-- imda_assessments — per-dimension scores + indicators (latest per dimension)
-- -----------------------------------------------------------------------------
CREATE TABLE imda_assessments (
    assessment_id     UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID             NOT NULL,
    dimension         imda_dimension   NOT NULL,
    score             SMALLINT         NOT NULL CHECK (score BETWEEN 0 AND 100),
    indicators        TEXT[]           NOT NULL DEFAULT '{}',
    notes             TEXT             NOT NULL DEFAULT '',
    assessed_by_gcid  UUID             NOT NULL,
    assessed_at       TIMESTAMPTZ      NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ      NOT NULL DEFAULT now()
);

CREATE INDEX idx_imda_assess_tenant_dim ON imda_assessments (tenant_id, dimension, assessed_at DESC);
CREATE INDEX idx_imda_assess_dim        ON imda_assessments (dimension);

CREATE OR REPLACE FUNCTION enforce_imda_assessments_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'imda_assessments is append-only: % rejected', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_imda_assess_no_update
    BEFORE UPDATE ON imda_assessments
    FOR EACH ROW EXECUTE FUNCTION enforce_imda_assessments_append_only();

CREATE TRIGGER trg_imda_assess_no_delete
    BEFORE DELETE ON imda_assessments
    FOR EACH ROW EXECUTE FUNCTION enforce_imda_assessments_append_only();

ALTER TABLE imda_assessments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON imda_assessments
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- imda_dimension_aggregates — pre-computed period aggregates per dimension
-- -----------------------------------------------------------------------------
CREATE TABLE imda_dimension_aggregates (
    aggregate_id      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID            NOT NULL,
    period_label      VARCHAR(16)     NOT NULL,                   -- e.g. '2026-Q2', '2026-05', '2026'
    period_from       TIMESTAMPTZ     NOT NULL,
    period_to         TIMESTAMPTZ     NOT NULL,
    dimension         imda_dimension  NOT NULL,
    json_aggregate    JSONB           NOT NULL,
    computed_at       TIMESTAMPTZ     NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, period_label, dimension),
    CHECK (period_to > period_from)
);

CREATE INDEX idx_imda_agg_tenant_dim ON imda_dimension_aggregates (tenant_id, dimension);
CREATE INDEX idx_imda_agg_period     ON imda_dimension_aggregates (period_label);

ALTER TABLE imda_dimension_aggregates ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON imda_dimension_aggregates
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- evidence_packs — IMDA evidence pack export records
-- -----------------------------------------------------------------------------
CREATE TABLE evidence_packs (
    pack_id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID         NOT NULL,
    period_label         VARCHAR(16)  NOT NULL,
    period_from          TIMESTAMPTZ  NOT NULL,
    period_to            TIMESTAMPTZ  NOT NULL,
    gcs_uri              TEXT         NOT NULL,
    audit_entry_count    INTEGER      NOT NULL DEFAULT 0 CHECK (audit_entry_count >= 0),
    assessment_count     INTEGER      NOT NULL DEFAULT 0 CHECK (assessment_count >= 0),
    bytes_estimated      BIGINT       NOT NULL DEFAULT 0 CHECK (bytes_estimated >= 0),
    generated_by_gcid    UUID         NOT NULL,
    generated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_evidence_packs_tenant ON evidence_packs (tenant_id, generated_at DESC);

ALTER TABLE evidence_packs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON evidence_packs
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

COMMIT;
