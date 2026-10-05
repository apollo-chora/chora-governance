-- =============================================================================
-- chora-governance : 0006_policy.sql
--
-- Domain        : Governance (supporting/platform)
-- Database      : chora_governance
-- Author        : Phase 5.B — pgx policy repository
-- Date          : 2026-05-13
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 5 D18) — Gatekeeper
-- Predecessors  : 0001_initial.sql (audit_log + imda_assessments + evidence_packs)
--                 0003_imda_evidence.sql (D1-D4 evidence tables)
--                 0005_outbox.sql (outbox primitive)
--
-- PURPOSE
--   Per CLAUDE.md §1 the Governance domain owns the Gatekeeper, whose rule
--   surface is the PolicyRule aggregate (internal/domain/policy/policy.go).
--   No persistent table existed until Phase 5.B — the in-memory repository
--   was the only implementation, blocking durable evaluator state across
--   server restarts and multi-replica deployments.
--
--   This migration adds the persistent `policy_rules` table mirroring the
--   in-memory domain shape:
--
--     - rule_id (UUID, PK) — UUIDv7 from domain.New()
--     - tenant_id (UUID, NULLABLE) — empty/NULL = global cross-tenant scope
--     - name (VARCHAR) — operator-facing rule label
--     - description (TEXT) — rationale + IMDA evidence link
--     - condition_expression (JSONB) — declarative condition AST
--                                      (Conditions list from domain — AND semantics)
--     - effect (ENUM permitted/denied) — maps to EnforcementMode (allow/deny)
--       NOTE: warn maps to permitted (logged but not blocked); the runtime
--       evaluator handles the three-mode distinction via condition_expression
--       metadata.
--     - active (BOOL) — Status.active = TRUE; Status.inactive = FALSE
--     - created_at / updated_at (TIMESTAMPTZ)
--
-- INVARIANTS
--   * UPDATE allowed (Save = upsert) — PolicyRule is mutable state, NOT
--     append-only evidence. Status flips (active↔inactive) + Version bumps
--     are handled at the domain layer.
--   * RLS enabled with tenant_isolation policy — mirrors audit_log pattern
--     from 0001_initial.sql line 96-97. Global rules (tenant_id IS NULL)
--     are visible regardless of session tenant.
--   * No outbox emission here — rule mutations are admin actions logged via
--     audit_log, not Pub/Sub events.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- ENUM — policy effect (binary at the table level; domain has 3-mode logic)
-- -----------------------------------------------------------------------------
CREATE TYPE policy_effect AS ENUM (
    'permitted',
    'denied'
);

-- -----------------------------------------------------------------------------
-- policy_rules — persistent PolicyRule aggregate state
-- -----------------------------------------------------------------------------
CREATE TABLE policy_rules (
    rule_id              UUID                 PRIMARY KEY,
    tenant_id            UUID                 NULL,              -- NULL = global
    name                 VARCHAR(256)         NOT NULL,
    description          TEXT                 NOT NULL DEFAULT '',
    condition_expression JSONB                NOT NULL DEFAULT '[]'::jsonb,
    effect               policy_effect        NOT NULL,
    active               BOOLEAN              NOT NULL DEFAULT TRUE,
    version              INTEGER              NOT NULL DEFAULT 1
                          CHECK (version >= 1),
    created_at           TIMESTAMPTZ          NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ          NOT NULL DEFAULT now()
);

-- Find rules for a given tenant ordered by recency.
CREATE INDEX idx_policy_rules_tenant
    ON policy_rules (tenant_id, updated_at DESC) WHERE tenant_id IS NOT NULL;

-- Find active global rules quickly.
CREATE INDEX idx_policy_rules_global_active
    ON policy_rules (updated_at DESC) WHERE tenant_id IS NULL AND active = TRUE;

-- Find applicable (active) rules for an evaluator pass.
CREATE INDEX idx_policy_rules_active
    ON policy_rules (active) WHERE active = TRUE;

-- updated_at trigger reuses governance_set_updated_at from 0001_initial.sql.
CREATE TRIGGER trg_policy_rules_updated_at
    BEFORE UPDATE ON policy_rules
    FOR EACH ROW EXECUTE FUNCTION governance_set_updated_at();

-- -----------------------------------------------------------------------------
-- RLS — tenant_isolation policy.
--
-- Global rules (tenant_id IS NULL) bypass the tenant check so they are visible
-- to every session. Per-tenant rules require chora.tenant_id = row.tenant_id.
-- Pattern adapted from audit_log (0001_initial.sql:96-97) and outbox_events
-- (0005_outbox.sql:99-105).
-- -----------------------------------------------------------------------------
ALTER TABLE policy_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON policy_rules
    FOR ALL USING (
        tenant_id IS NULL
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

COMMIT;

-- =============================================================================
-- END 0006_policy.sql
--
-- Follow-up:
--   - Phase 5.B.2 — internal/adapter/pg/policy_repository.go implements
--     policy.Repository against this table.
--   - Future: per-rule evaluation metrics in observability domain.
-- =============================================================================
