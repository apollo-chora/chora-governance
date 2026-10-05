-- =============================================================================
-- chora-governance : 0003_imda_evidence.sql
--
-- Domain        : Governance (supporting/platform)
-- Database      : chora_governance
-- Author        : agent A-Governance (S7.2 — IMDA D1-D4 evidence)
-- Date          : 2026-05-10
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 5 D18) — IMDA NorthStar
-- ADR           : ADR-141 — IMDA Dimension Labels Reconciliation
-- Predecessors  : 0001_initial.sql (audit_log + imda_assessments + evidence_packs)
--                 0002_imda_canonical_labels.sql (ENUM + data canonicalisation)
-- Jira          : CHO-1473
--
-- PURPOSE
--   Per audit-platform-fillgaps.md §3.3 + §5, all 11 IMDA D1-D4 production
--   evidence tables are missing. The current schema only ships a generic
--   imda_assessments + an audit_log hash-chain — the rich evidence projection
--   that IMDA evidence-pack export requires is absent.
--
--   This migration adds the 11 net-new evidence tables aligned to the
--   AssessorFlow o-plus-dashboard gold standard (per audit-platform-fillgaps.md
--   §5 + R-PLAT-2 risk):
--
--     D1 accountability (1 table)
--       - accountability_evidence
--
--     D2 transparency (3 tables)
--       - model_card_registry
--       - data_card_registry
--       - decision_explanation
--
--     D3 safety_and_robustness (5 tables)
--       - red_team_runs
--       - eval_runs
--       - cost_anomalies
--       - circuit_breaker_state
--       - quarantine_state
--
--     D4 fairness_and_human_oversight (2 tables)
--       - bias_test_runs
--       - hitl_decision_log
--
--   Plus 1 supporting table for guardrail policy violation tracking:
--
--       - policy_violation_log (ContentPolicyViolationLog per Tier 3 D9)
--
-- LIFECYCLE STAGE TAGGING (per envelope.proto field 15 / CLAUDE.md §6)
--   Every evidence row carries imda_lifecycle_stage enum:
--     - 'ci_pre_merge'  : CI/pre-merge linting + static analysis evidence
--     - 'pre_deploy'    : red-team + eval runs in CI before deploy gates
--     - 'runtime'       : default for runtime-emitted evidence
--     - 'post_deploy'   : incident reports, drift detection, post-mortem
--
-- INVARIANTS (all 11 + policy_violation_log)
--   * APPEND-ONLY (UPDATE/DELETE rejected by trigger) — except
--     circuit_breaker_state + quarantine_state which are state machines and
--     allow UPDATE; their state transitions are recorded in companion
--     transition_audit columns + emit events.
--   * RLS enabled with tenant_isolation policy on tenant-scoped tables.
--   * Idempotent on event_id (UNIQUE) so re-delivery from at-least-once
--     Pub/Sub does not duplicate evidence.
--
-- THREE-AUDIENCE EXPLAINABILITY VIEWS (per Tier 4 D16 role-driven visibility)
--   At the bottom of this migration we create 3 views over decision_explanation
--   filtered by audience enum: learner / instructor_admin / auditor. The
--   API layer uses role grants to choose which view to query.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- ENUMs (additive — keep prior types from 0001_initial.sql intact)
-- -----------------------------------------------------------------------------

-- 4-stage IMDA pipeline lifecycle classifier per envelope.proto field 15.
-- Mirrors chora-common/envelope/envelope.go canonicalLifecycleStages.
CREATE TYPE imda_lifecycle_stage AS ENUM (
    'ci_pre_merge',
    'pre_deploy',
    'runtime',
    'post_deploy'
);

-- Three-Audience explainability per Tier 4 D16. Role-conditional visibility,
-- NOT toggle (Topology F removed).
CREATE TYPE explanation_audience AS ENUM (
    'learner',
    'instructor_admin',
    'auditor'
);

-- Circuit breaker tri-state per agent-resilience skill.
CREATE TYPE circuit_breaker_state_kind AS ENUM (
    'closed',
    'half_open',
    'open'
);

-- HITL decision verdict.
CREATE TYPE hitl_decision_verdict AS ENUM (
    'approve',
    'reject',
    'edit'
);

-- Autonomy levels per imda-governance-4-dimensions skill + ADR-141.
-- Level 3 (out-of-band autonomous) is PROHIBITED — not present in enum.
CREATE TYPE autonomy_level AS ENUM (
    'hootl',     -- Level 0: human-out-of-the-loop (low-stakes, fully autonomous)
    'hotl',      -- Level 1: human-on-the-loop   (autonomous + monitoring)
    'hitl_l0',   -- Level 2: human-in-the-loop, sampling review
    'hitl_l1',   -- Level 2: human-in-the-loop, mandatory per Nth output
    'hitl_l2'    -- Level 2: human-in-the-loop, mandatory every output
);

-- -----------------------------------------------------------------------------
-- D1 — accountability_evidence
--
-- Per-agent decision provenance + owner GCID. Append-only, idempotent on
-- event_id, RLS by tenant_id.
-- -----------------------------------------------------------------------------
CREATE TABLE accountability_evidence (
    id                    UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id              UUID                 NOT NULL UNIQUE,
    tenant_id             UUID                 NOT NULL,
    agent_id              VARCHAR(128)         NOT NULL,
    owner_gcid            UUID                 NOT NULL,
    decision_id           VARCHAR(128)         NOT NULL,
    decision_type         VARCHAR(64)          NOT NULL,
    decision_provenance   JSONB                NOT NULL DEFAULT '{}'::jsonb,
    evidence_hash         CHAR(64)             NOT NULL,
    lifecycle_stage       imda_lifecycle_stage NOT NULL DEFAULT 'runtime',
    traceparent           VARCHAR(64)          NULL,
    recorded_at           TIMESTAMPTZ          NOT NULL DEFAULT now()
);

CREATE INDEX idx_accountability_evidence_tenant
    ON accountability_evidence (tenant_id, recorded_at DESC);
CREATE INDEX idx_accountability_evidence_agent
    ON accountability_evidence (agent_id);
CREATE INDEX idx_accountability_evidence_owner
    ON accountability_evidence (owner_gcid);
CREATE INDEX idx_accountability_evidence_decision
    ON accountability_evidence (decision_id);
CREATE INDEX idx_accountability_evidence_lifecycle
    ON accountability_evidence (lifecycle_stage);

-- -----------------------------------------------------------------------------
-- D2 — model_card_registry
-- -----------------------------------------------------------------------------
CREATE TABLE model_card_registry (
    id                       UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id                 UUID                 NOT NULL UNIQUE,
    tenant_id                UUID                 NOT NULL,
    model_id                 VARCHAR(256)         NOT NULL,
    model_version            VARCHAR(64)          NOT NULL,
    card_md                  TEXT                 NOT NULL,
    training_data_summary    TEXT                 NOT NULL DEFAULT '',
    intended_uses            TEXT                 NOT NULL DEFAULT '',
    limitations              TEXT                 NOT NULL DEFAULT '',
    fairness_attestations    JSONB                NOT NULL DEFAULT '{}'::jsonb,
    lifecycle_stage          imda_lifecycle_stage NOT NULL DEFAULT 'runtime',
    registered_at            TIMESTAMPTZ          NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, model_id, model_version)
);

CREATE INDEX idx_model_card_registry_tenant
    ON model_card_registry (tenant_id, registered_at DESC);
CREATE INDEX idx_model_card_registry_model
    ON model_card_registry (model_id);

-- -----------------------------------------------------------------------------
-- D2 — data_card_registry
-- -----------------------------------------------------------------------------
CREATE TABLE data_card_registry (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID                 NOT NULL UNIQUE,
    tenant_id           UUID                 NOT NULL,
    dataset_id          VARCHAR(256)         NOT NULL,
    dataset_version     VARCHAR(64)          NOT NULL,
    card_md             TEXT                 NOT NULL,
    schema_jsonb        JSONB                NOT NULL DEFAULT '{}'::jsonb,
    provenance          TEXT                 NOT NULL DEFAULT '',
    lifecycle_stage     imda_lifecycle_stage NOT NULL DEFAULT 'runtime',
    registered_at       TIMESTAMPTZ          NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, dataset_id, dataset_version)
);

CREATE INDEX idx_data_card_registry_tenant
    ON data_card_registry (tenant_id, registered_at DESC);
CREATE INDEX idx_data_card_registry_dataset
    ON data_card_registry (dataset_id);

-- -----------------------------------------------------------------------------
-- D2 — decision_explanation (Three-Audience: learner/instructor_admin/auditor)
-- -----------------------------------------------------------------------------
CREATE TABLE decision_explanation (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID                 NOT NULL UNIQUE,
    tenant_id           UUID                 NOT NULL,
    decision_id         VARCHAR(128)         NOT NULL,
    audience            explanation_audience NOT NULL,
    explanation_md      TEXT                 NOT NULL,
    confidence_score    DOUBLE PRECISION     NOT NULL DEFAULT 0
        CHECK (confidence_score >= 0 AND confidence_score <= 1),
    lifecycle_stage     imda_lifecycle_stage NOT NULL DEFAULT 'runtime',
    generated_at        TIMESTAMPTZ          NOT NULL DEFAULT now()
);

CREATE INDEX idx_decision_explanation_tenant_decision
    ON decision_explanation (tenant_id, decision_id);
CREATE INDEX idx_decision_explanation_audience
    ON decision_explanation (audience);
CREATE INDEX idx_decision_explanation_lifecycle
    ON decision_explanation (lifecycle_stage);

-- -----------------------------------------------------------------------------
-- D3 — red_team_runs
-- -----------------------------------------------------------------------------
CREATE TABLE red_team_runs (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID                 NOT NULL UNIQUE,
    tenant_id           UUID                 NOT NULL,
    run_id              VARCHAR(128)         NOT NULL,
    agent_id            VARCHAR(128)         NOT NULL,
    scenario_jsonb      JSONB                NOT NULL DEFAULT '{}'::jsonb,
    verdict             VARCHAR(32)          NOT NULL,
    findings_jsonb      JSONB                NOT NULL DEFAULT '{}'::jsonb,
    lifecycle_stage     imda_lifecycle_stage NOT NULL DEFAULT 'pre_deploy',
    run_at              TIMESTAMPTZ          NOT NULL DEFAULT now()
);

CREATE INDEX idx_red_team_runs_tenant
    ON red_team_runs (tenant_id, run_at DESC);
CREATE INDEX idx_red_team_runs_agent
    ON red_team_runs (agent_id);
CREATE INDEX idx_red_team_runs_verdict
    ON red_team_runs (verdict);

-- -----------------------------------------------------------------------------
-- D3 — eval_runs
-- -----------------------------------------------------------------------------
CREATE TABLE eval_runs (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID                 NOT NULL UNIQUE,
    tenant_id           UUID                 NOT NULL,
    run_id              VARCHAR(128)         NOT NULL,
    agent_id            VARCHAR(128)         NOT NULL,
    eval_suite          VARCHAR(128)         NOT NULL,
    score               DOUBLE PRECISION     NOT NULL DEFAULT 0,
    baseline_score      DOUBLE PRECISION     NOT NULL DEFAULT 0,
    regressed           BOOLEAN              NOT NULL DEFAULT FALSE,
    lifecycle_stage     imda_lifecycle_stage NOT NULL DEFAULT 'pre_deploy',
    run_at              TIMESTAMPTZ          NOT NULL DEFAULT now()
);

CREATE INDEX idx_eval_runs_tenant
    ON eval_runs (tenant_id, run_at DESC);
CREATE INDEX idx_eval_runs_agent_suite
    ON eval_runs (agent_id, eval_suite);
CREATE INDEX idx_eval_runs_regressed
    ON eval_runs (regressed) WHERE regressed = TRUE;

-- -----------------------------------------------------------------------------
-- D3 — cost_anomalies
-- -----------------------------------------------------------------------------
CREATE TABLE cost_anomalies (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID                 NOT NULL UNIQUE,
    tenant_id           UUID                 NOT NULL,
    anomaly_id          VARCHAR(128)         NOT NULL,
    agent_id            VARCHAR(128)         NOT NULL,
    baseline_micros     BIGINT               NOT NULL DEFAULT 0,
    observed_micros     BIGINT               NOT NULL DEFAULT 0,
    sigma_factor        DOUBLE PRECISION     NOT NULL DEFAULT 0,
    lifecycle_stage     imda_lifecycle_stage NOT NULL DEFAULT 'runtime',
    recorded_at         TIMESTAMPTZ          NOT NULL DEFAULT now()
);

CREATE INDEX idx_cost_anomalies_tenant
    ON cost_anomalies (tenant_id, recorded_at DESC);
CREATE INDEX idx_cost_anomalies_agent
    ON cost_anomalies (agent_id);

-- -----------------------------------------------------------------------------
-- D3 — circuit_breaker_state (state machine — UPDATE allowed; transitions audited)
-- -----------------------------------------------------------------------------
CREATE TABLE circuit_breaker_state (
    id                       UUID                       PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                UUID                       NOT NULL,
    agent_id                 VARCHAR(128)               NOT NULL,
    state                    circuit_breaker_state_kind NOT NULL DEFAULT 'closed',
    failure_count            INTEGER                    NOT NULL DEFAULT 0,
    lifecycle_stage          imda_lifecycle_stage       NOT NULL DEFAULT 'runtime',
    last_transitioned_at     TIMESTAMPTZ                NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, agent_id)
);

CREATE INDEX idx_circuit_breaker_state_tenant
    ON circuit_breaker_state (tenant_id);
CREATE INDEX idx_circuit_breaker_state_open
    ON circuit_breaker_state (state) WHERE state = 'open';

-- -----------------------------------------------------------------------------
-- D3 — quarantine_state (state machine — UPDATE allowed when releasing)
-- -----------------------------------------------------------------------------
CREATE TABLE quarantine_state (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID                 NOT NULL,
    agent_id            VARCHAR(128)         NOT NULL,
    reason              TEXT                 NOT NULL,
    lifecycle_stage     imda_lifecycle_stage NOT NULL DEFAULT 'runtime',
    quarantined_at      TIMESTAMPTZ          NOT NULL DEFAULT now(),
    released_at         TIMESTAMPTZ          NULL
);

CREATE INDEX idx_quarantine_state_tenant
    ON quarantine_state (tenant_id);
CREATE INDEX idx_quarantine_state_active
    ON quarantine_state (agent_id) WHERE released_at IS NULL;

-- -----------------------------------------------------------------------------
-- D4 — bias_test_runs
-- -----------------------------------------------------------------------------
CREATE TABLE bias_test_runs (
    id                       UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id                 UUID                 NOT NULL UNIQUE,
    tenant_id                UUID                 NOT NULL,
    run_id                   VARCHAR(128)         NOT NULL,
    agent_id                 VARCHAR(128)         NOT NULL,
    protected_attribute      VARCHAR(64)          NOT NULL,
    test_type                VARCHAR(64)          NOT NULL,
    score                    DOUBLE PRECISION     NOT NULL DEFAULT 0,
    threshold                DOUBLE PRECISION     NOT NULL DEFAULT 0,
    passed                   BOOLEAN              NOT NULL DEFAULT FALSE,
    lifecycle_stage          imda_lifecycle_stage NOT NULL DEFAULT 'pre_deploy',
    run_at                   TIMESTAMPTZ          NOT NULL DEFAULT now()
);

CREATE INDEX idx_bias_test_runs_tenant
    ON bias_test_runs (tenant_id, run_at DESC);
CREATE INDEX idx_bias_test_runs_attribute
    ON bias_test_runs (protected_attribute);
CREATE INDEX idx_bias_test_runs_failed
    ON bias_test_runs (passed) WHERE passed = FALSE;

-- -----------------------------------------------------------------------------
-- D4 — hitl_decision_log
-- -----------------------------------------------------------------------------
CREATE TABLE hitl_decision_log (
    id                  UUID                  PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID                  NOT NULL UNIQUE,
    tenant_id           UUID                  NOT NULL,
    decision_id         VARCHAR(128)          NOT NULL,
    run_id              VARCHAR(128)          NOT NULL,
    operator_gcid       UUID                  NOT NULL,
    decision            hitl_decision_verdict NOT NULL,
    autonomy_level      autonomy_level        NOT NULL,
    edit_payload        JSONB                 NOT NULL DEFAULT '{}'::jsonb,
    lifecycle_stage     imda_lifecycle_stage  NOT NULL DEFAULT 'runtime',
    decided_at          TIMESTAMPTZ           NOT NULL DEFAULT now()
);

CREATE INDEX idx_hitl_decision_log_tenant
    ON hitl_decision_log (tenant_id, decided_at DESC);
CREATE INDEX idx_hitl_decision_log_operator
    ON hitl_decision_log (operator_gcid);
CREATE INDEX idx_hitl_decision_log_decision
    ON hitl_decision_log (decision);
CREATE INDEX idx_hitl_decision_log_autonomy
    ON hitl_decision_log (autonomy_level);

-- -----------------------------------------------------------------------------
-- ContentPolicyViolationLog (per Tier 3 D9; from S3 Guardrail subscriber)
-- -----------------------------------------------------------------------------
CREATE TABLE policy_violation_log (
    id                  UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id            UUID                 NOT NULL UNIQUE,
    tenant_id           UUID                 NOT NULL,
    agent_id            VARCHAR(128)         NOT NULL,
    policy_name         VARCHAR(128)         NOT NULL,
    severity            VARCHAR(32)          NOT NULL,
    detector            VARCHAR(64)          NOT NULL,
    detected_payload    JSONB                NOT NULL DEFAULT '{}'::jsonb,
    lifecycle_stage     imda_lifecycle_stage NOT NULL DEFAULT 'runtime',
    detected_at         TIMESTAMPTZ          NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_violation_log_tenant
    ON policy_violation_log (tenant_id, detected_at DESC);
CREATE INDEX idx_policy_violation_log_agent
    ON policy_violation_log (agent_id);
CREATE INDEX idx_policy_violation_log_severity
    ON policy_violation_log (severity);

-- =============================================================================
-- APPEND-ONLY triggers (rejected UPDATE/DELETE) for evidence tables
--
-- circuit_breaker_state + quarantine_state are state machines — UPDATE
-- allowed; we audit transitions via emit-on-change in domain code.
-- =============================================================================

CREATE OR REPLACE FUNCTION enforce_evidence_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'IMDA evidence row is append-only: % rejected on table %',
        TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

-- D1
CREATE TRIGGER trg_accountability_evidence_no_update
    BEFORE UPDATE ON accountability_evidence
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_accountability_evidence_no_delete
    BEFORE DELETE ON accountability_evidence
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

-- D2
CREATE TRIGGER trg_model_card_registry_no_update
    BEFORE UPDATE ON model_card_registry
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_model_card_registry_no_delete
    BEFORE DELETE ON model_card_registry
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

CREATE TRIGGER trg_data_card_registry_no_update
    BEFORE UPDATE ON data_card_registry
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_data_card_registry_no_delete
    BEFORE DELETE ON data_card_registry
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

CREATE TRIGGER trg_decision_explanation_no_update
    BEFORE UPDATE ON decision_explanation
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_decision_explanation_no_delete
    BEFORE DELETE ON decision_explanation
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

-- D3 (run/anomaly tables; circuit_breaker + quarantine are state, NOT append-only)
CREATE TRIGGER trg_red_team_runs_no_update
    BEFORE UPDATE ON red_team_runs
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_red_team_runs_no_delete
    BEFORE DELETE ON red_team_runs
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

CREATE TRIGGER trg_eval_runs_no_update
    BEFORE UPDATE ON eval_runs
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_eval_runs_no_delete
    BEFORE DELETE ON eval_runs
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

CREATE TRIGGER trg_cost_anomalies_no_update
    BEFORE UPDATE ON cost_anomalies
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_cost_anomalies_no_delete
    BEFORE DELETE ON cost_anomalies
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

-- D4
CREATE TRIGGER trg_bias_test_runs_no_update
    BEFORE UPDATE ON bias_test_runs
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_bias_test_runs_no_delete
    BEFORE DELETE ON bias_test_runs
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

CREATE TRIGGER trg_hitl_decision_log_no_update
    BEFORE UPDATE ON hitl_decision_log
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_hitl_decision_log_no_delete
    BEFORE DELETE ON hitl_decision_log
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

-- Policy violation log
CREATE TRIGGER trg_policy_violation_log_no_update
    BEFORE UPDATE ON policy_violation_log
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_policy_violation_log_no_delete
    BEFORE DELETE ON policy_violation_log
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

-- =============================================================================
-- Row-Level Security (RLS) — tenant isolation per multi-tenant-rls skill
-- =============================================================================

-- D1
ALTER TABLE accountability_evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON accountability_evidence
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- D2
ALTER TABLE model_card_registry ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON model_card_registry
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

ALTER TABLE data_card_registry ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON data_card_registry
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

ALTER TABLE decision_explanation ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON decision_explanation
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- D3
ALTER TABLE red_team_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON red_team_runs
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

ALTER TABLE eval_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON eval_runs
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

ALTER TABLE cost_anomalies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cost_anomalies
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

ALTER TABLE circuit_breaker_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON circuit_breaker_state
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

ALTER TABLE quarantine_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON quarantine_state
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- D4
ALTER TABLE bias_test_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON bias_test_runs
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

ALTER TABLE hitl_decision_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON hitl_decision_log
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- ContentPolicyViolationLog
ALTER TABLE policy_violation_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policy_violation_log
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- =============================================================================
-- Three-Audience Explainability views (per Tier 4 D16: role-driven visibility)
--
-- Filter decision_explanation by audience enum. Each role grant maps to one
-- view; cross-audience leakage is prevented by RLS + view definition.
-- =============================================================================

CREATE VIEW decision_explanation_for_learner AS
    SELECT id, event_id, tenant_id, decision_id, audience,
           explanation_md, confidence_score, lifecycle_stage, generated_at
    FROM decision_explanation
    WHERE audience = 'learner';

CREATE VIEW decision_explanation_for_instructor_admin AS
    SELECT id, event_id, tenant_id, decision_id, audience,
           explanation_md, confidence_score, lifecycle_stage, generated_at
    FROM decision_explanation
    WHERE audience IN ('instructor_admin', 'learner');

CREATE VIEW decision_explanation_for_auditor AS
    SELECT id, event_id, tenant_id, decision_id, audience,
           explanation_md, confidence_score, lifecycle_stage, generated_at
    FROM decision_explanation;

COMMIT;

-- =============================================================================
-- END 0003_imda_evidence.sql
--
-- Follow-up:
--   - chora-infra Terraform: GCS bucket chora-evidence-packs-{env} (M10/M14)
--   - Cloud Run Job for long-running evidence-pack export (M14 onward)
-- =============================================================================
