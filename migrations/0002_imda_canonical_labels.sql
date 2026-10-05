-- =============================================================================
-- chora-governance : 0002_imda_canonical_labels.sql
--
-- Domain        : Governance (supporting/platform)
-- Database      : chora_governance
-- Author        : ARCH-2 (db-migrations follow-up to ADR-141 §4 step 6)
-- Date          : 2026-05-09
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 5 D18) — IMDA NorthStar
-- ADR           : ADR-141 — IMDA Dimension Labels Reconciliation
-- Predecessor   : 0001_initial.sql (ENUM imda_dimension with v1 values)
--
-- PURPOSE
--   ADR-141 §4 step 1-5 (CODE rename) shipped earlier in this release; the DB
--   side was deferred to this follow-up per ADR-141 §4 step 6. This migration
--   completes the alias-mode roll-out by:
--
--     1. Adding the four canonical AssessorFlow / IMDA MGF v2 + AI Verify
--        gold-standard labels to the imda_dimension ENUM.
--     2. Data-migrating existing rows in tables that reference imda_dimension
--        (imda_assessments + imda_dimension_aggregates) from the v1 labels to
--        their canonical equivalents.
--
--   The mapping (per ADR-141 §2 mapping table) is:
--
--     v1 (deprecated alias)        →  canonical (gold standard)        Dim
--     ----------------------------    ------------------------------   ----
--     'risk_levels'                →  'accountability'                 D1
--     'stakeholder_interaction'    →  'transparency'                   D2
--     'internal_governance'        →  'safety_and_robustness'          D3
--     'operations_management'      →  'fairness_and_human_oversight'   D4
--
-- ALIAS-MODE WINDOW (ADR-141 §3)
--   The four v1 values are KEPT in the ENUM during the deprecation window
--   (one release / next chora-governance major version bump). They are NOT
--   dropped here. A follow-up migration AFTER the deprecation window — when
--   no in-flight evidence references v1 values and Canonicalise() is removed
--   from the Go domain — will:
--
--     - DROP the four v1 ENUM values via the standard rename-type / recreate
--       pattern (PostgreSQL has no ALTER TYPE ... DROP VALUE).
--     - Retire ADR-141 §3 alias mode.
--
--   See ADR-141 §3 for the deprecation contract.
--
-- TRANSACTIONALITY
--   ALTER TYPE ... ADD VALUE cannot run inside a transaction block in
--   PostgreSQL <12 and must be the first statement of its own implicit
--   transaction in PostgreSQL >=12 — but it ALSO cannot share a transaction
--   with subsequent statements that reference the new value. We therefore
--   split this migration into two phases that the migration runner MUST
--   execute as separate transactions:
--
--     Phase A (this file, top half) — ENUM additions only.
--     Phase B (this file, bottom half) — UPDATE statements once the new
--                                        labels are committed.
--
--   Both halves are idempotent (re-runnable). The "STATEMENT BREAK" marker
--   below tells the migration runner to commit Phase A before Phase B starts.
--   If your migration runner does not honour the marker, split this file
--   into 0002a_*.sql + 0002b_*.sql.
--
-- IDEMPOTENCY
--   - Phase A guards each ALTER TYPE with a pg_enum existence check; safe to
--     re-run after partial failure.
--   - Phase B's UPDATE statements are naturally idempotent — once a row's
--     dimension is canonical, a re-run matches no v1 rows and is a no-op.
--
-- BLAST RADIUS
--   - imda_assessments      (append-only, RLS-protected, idx_imda_assess_dim)
--   - imda_dimension_aggregates (RLS-protected, idx_imda_agg_tenant_dim,
--                                UNIQUE(tenant_id, period_label, dimension))
--
--   Updates on imda_assessments will be REJECTED by trg_imda_assess_no_update
--   under normal RLS-enabled connections. Run this migration as the migration
--   role with session_replication_role = 'replica' OR temporarily disable the
--   trigger as documented in Phase B. The append-only invariant is a domain
--   rule; the schema migration role is by definition exempt.
--
--   The UNIQUE(tenant_id, period_label, dimension) constraint on
--   imda_dimension_aggregates means a tenant cannot have BOTH a v1-keyed and
--   a canonical-keyed aggregate for the same period — collisions would have
--   indicated a code-side bug. Phase B asserts no such collisions exist
--   before performing the UPDATE.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Phase A — ENUM additions (must commit before Phase B)
--
-- ALTER TYPE ... ADD VALUE is not idempotent in PostgreSQL by default; we
-- guard each call with a pg_enum existence check. The order does NOT matter
-- because we are only adding values (not reordering); existing v1 values
-- keep their oid and therefore their sort position.
-- -----------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'imda_dimension' AND e.enumlabel = 'accountability'
    ) THEN
        ALTER TYPE imda_dimension ADD VALUE 'accountability';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'imda_dimension' AND e.enumlabel = 'transparency'
    ) THEN
        ALTER TYPE imda_dimension ADD VALUE 'transparency';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'imda_dimension' AND e.enumlabel = 'safety_and_robustness'
    ) THEN
        ALTER TYPE imda_dimension ADD VALUE 'safety_and_robustness';
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'imda_dimension' AND e.enumlabel = 'fairness_and_human_oversight'
    ) THEN
        ALTER TYPE imda_dimension ADD VALUE 'fairness_and_human_oversight';
    END IF;
END
$$;

-- =============================================================================
-- STATEMENT BREAK — migration runner MUST commit before continuing.
-- The four canonical ENUM values must be visible to subsequent statements;
-- PostgreSQL does not allow new ENUM values to be referenced in the same
-- transaction in which they were added.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Phase B — Data migration of rows still referencing v1 ENUM labels
--
-- The append-only triggers on imda_assessments are domain invariants for the
-- application role; the migration role is exempt by convention. We use
-- ALTER TABLE ... DISABLE TRIGGER scoped to this transaction so that:
--   - the change is local (no concurrent writers see a window where the
--     trigger is missing),
--   - re-enable is guaranteed in the same transaction commit/rollback.
-- -----------------------------------------------------------------------------

BEGIN;

-- Defensive collision check on imda_dimension_aggregates: if a tenant has
-- both a v1-keyed and a canonical-keyed aggregate for the same period, the
-- UNIQUE constraint will fail on UPDATE. Surface that as a clear error
-- BEFORE the UPDATE so operators know which row to reconcile manually.
DO $$
DECLARE
    collision_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO collision_count
    FROM (
        SELECT tenant_id, period_label
        FROM imda_dimension_aggregates
        WHERE dimension::text IN (
            'risk_levels', 'stakeholder_interaction',
            'internal_governance', 'operations_management',
            'accountability', 'transparency',
            'safety_and_robustness', 'fairness_and_human_oversight'
        )
        GROUP BY tenant_id, period_label,
                 CASE dimension::text
                     WHEN 'risk_levels'             THEN 'accountability'
                     WHEN 'stakeholder_interaction' THEN 'transparency'
                     WHEN 'internal_governance'     THEN 'safety_and_robustness'
                     WHEN 'operations_management'   THEN 'fairness_and_human_oversight'
                     ELSE dimension::text
                 END
        HAVING COUNT(*) > 1
    ) AS dupes;

    IF collision_count > 0 THEN
        RAISE EXCEPTION 'imda_dimension_aggregates has % v1/canonical collision(s) on (tenant_id, period_label) — reconcile manually before re-running 0002_imda_canonical_labels.sql', collision_count;
    END IF;
END
$$;

-- imda_assessments — disable append-only triggers for migration role only.
ALTER TABLE imda_assessments DISABLE TRIGGER trg_imda_assess_no_update;

UPDATE imda_assessments
   SET dimension = 'accountability'::imda_dimension
 WHERE dimension::text = 'risk_levels';

UPDATE imda_assessments
   SET dimension = 'transparency'::imda_dimension
 WHERE dimension::text = 'stakeholder_interaction';

UPDATE imda_assessments
   SET dimension = 'safety_and_robustness'::imda_dimension
 WHERE dimension::text = 'internal_governance';

UPDATE imda_assessments
   SET dimension = 'fairness_and_human_oversight'::imda_dimension
 WHERE dimension::text = 'operations_management';

ALTER TABLE imda_assessments ENABLE TRIGGER trg_imda_assess_no_update;

-- imda_dimension_aggregates — no append-only trigger; straight UPDATE.
UPDATE imda_dimension_aggregates
   SET dimension = 'accountability'::imda_dimension
 WHERE dimension::text = 'risk_levels';

UPDATE imda_dimension_aggregates
   SET dimension = 'transparency'::imda_dimension
 WHERE dimension::text = 'stakeholder_interaction';

UPDATE imda_dimension_aggregates
   SET dimension = 'safety_and_robustness'::imda_dimension
 WHERE dimension::text = 'internal_governance';

UPDATE imda_dimension_aggregates
   SET dimension = 'fairness_and_human_oversight'::imda_dimension
 WHERE dimension::text = 'operations_management';

-- Post-migration assertion: NO rows should still reference v1 labels.
DO $$
DECLARE
    leftover_assessments INTEGER;
    leftover_aggregates  INTEGER;
BEGIN
    SELECT COUNT(*) INTO leftover_assessments
    FROM imda_assessments
    WHERE dimension::text IN (
        'risk_levels', 'stakeholder_interaction',
        'internal_governance', 'operations_management'
    );

    SELECT COUNT(*) INTO leftover_aggregates
    FROM imda_dimension_aggregates
    WHERE dimension::text IN (
        'risk_levels', 'stakeholder_interaction',
        'internal_governance', 'operations_management'
    );

    IF leftover_assessments > 0 OR leftover_aggregates > 0 THEN
        RAISE EXCEPTION 'ADR-141 data migration incomplete: imda_assessments=% imda_dimension_aggregates=% rows still on v1 labels',
            leftover_assessments, leftover_aggregates;
    END IF;
END
$$;

COMMIT;

-- =============================================================================
-- END 0002_imda_canonical_labels.sql
--
-- Follow-up (post-deprecation, separate migration 000N_imda_drop_v1_labels.sql):
--   1. Confirm zero references to v1 labels in code + ledger + evidence packs.
--   2. Retire Canonicalise() and the deprecated_aliases map in imda.go.
--   3. Drop v1 ENUM values via the rename-type/recreate pattern, since
--      PostgreSQL has no native ALTER TYPE ... DROP VALUE.
-- =============================================================================
