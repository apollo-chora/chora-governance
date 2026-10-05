-- =============================================================================
-- chora-governance : 0011_ai_transparency.up.sql
--
-- Domain        : Governance (supporting/platform)
-- Database      : chora_governance
-- ADR           : ADR-225 — AI Transparency Notice + content provenance
-- IMDA          : D2 transparency (ISO/IEC 25059:2023 "User Controllability —
--                 consent UI presence")
-- Predecessors  : 0003_imda_evidence.sql (append-only + RLS patterns reused),
--                 0006_policy.sql (platform-config-no-RLS pattern reused),
--                 9999_grant_app_roles.sql (runs last; grants app_rw/app_ro)
--
-- PURPOSE
--   The ADR-225 server-side backbone (RECORD + SERVE). Two tables:
--
--   1. transparency_disclosure_version — CONFIG-AS-DATA (ADR-225 §D5.1). The
--      versioned disclosure copy served to the FE (no inline config). PLATFORM
--      scope — no tenant_id, no RLS (mirrors policy_rules): the disclosure is
--      platform-wide. One row is `active` per scope at a time (partial unique
--      index). Locales JSONB carries locale -> variant -> copy.
--
--   2. ai_transparency_acknowledgement — APPEND-ONLY transparency EVIDENCE
--      (ADR-225 §D3.2 / §D4.1). One row per (tenant, GCID, disclosure_version):
--      the learner acknowledged the notice. RLS tenant_isolation (defence in
--      depth + auditor tenant-scoped view). Feeds O+ D2 + the must_acknowledge
--      read-model.
--
-- SCOPE NOTE (per-GCID portability — ADR-225 §D6.1)
--   The acknowledgement is conceptually per-GCID (portable). This backbone
--   RLS-partitions it by tenant (the coordinator's requirement + auditor
--   scoping), so a returning learner re-acknowledges once per tenant they use.
--   That fails SAFE (more disclosure, never fewer; never a gate). FULL
--   cross-tenant portability (a GCID-keyed read transcending the tenant RLS
--   boundary via a dual-GUC `gcid OR tenant_id` policy) is a flagged follow-up.
--
-- INVARIANTS
--   * ai_transparency_acknowledgement is APPEND-ONLY (UPDATE/DELETE rejected by
--     trigger, reusing enforce_evidence_append_only() from 0003).
--   * Idempotent on (tenant_id, gcid, disclosure_version) — at-least-once
--     re-delivery / double-submit collapses to one row.
--   * RLS on the acknowledgement table keyed on chora.tenant_id GUC.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- ENUMs (additive)
-- -----------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'disclosure_status') THEN
        CREATE TYPE disclosure_status AS ENUM ('draft', 'active', 'archived');
    END IF;
END$$;

-- -----------------------------------------------------------------------------
-- 1. transparency_disclosure_version — config-as-data (platform, no RLS)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS transparency_disclosure_version (
    version                     TEXT PRIMARY KEY,
    status                      disclosure_status NOT NULL DEFAULT 'draft',
    requires_reacknowledgement  BOOLEAN NOT NULL DEFAULT false,
    effective_from              TIMESTAMPTZ NOT NULL,
    scope                       TEXT NOT NULL DEFAULT 'platform',
    locales                     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by                  TEXT NOT NULL DEFAULT '',
    approved_by                 TEXT NOT NULL DEFAULT '',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one ACTIVE version per scope (the current disclosure).
CREATE UNIQUE INDEX IF NOT EXISTS uq_disclosure_active_per_scope
    ON transparency_disclosure_version (scope)
    WHERE status = 'active';

-- -----------------------------------------------------------------------------
-- 2. ai_transparency_acknowledgement — append-only evidence (tenant RLS)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ai_transparency_acknowledgement (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    gcid                UUID NOT NULL,
    disclosure_version  TEXT NOT NULL,
    surface             TEXT NOT NULL,
    scope               TEXT NOT NULL,
    first_shown_at      TIMESTAMPTZ NOT NULL,
    acknowledged_at     TIMESTAMPTZ NOT NULL,
    locale              TEXT NOT NULL DEFAULT 'en',
    minor_mode          BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotency: one ack per (tenant, learner, disclosure version).
    CONSTRAINT uq_ai_transparency_ack UNIQUE (tenant_id, gcid, disclosure_version)
);

-- must_acknowledge read: latest ack for a learner (within tenant RLS scope).
CREATE INDEX IF NOT EXISTS idx_ai_transparency_ack_gcid
    ON ai_transparency_acknowledgement (gcid, acknowledged_at DESC);

-- Append-only enforcement (reuse the 0003 trigger function).
CREATE TRIGGER trg_ai_transparency_ack_no_update
    BEFORE UPDATE ON ai_transparency_acknowledgement
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();
CREATE TRIGGER trg_ai_transparency_ack_no_delete
    BEFORE DELETE ON ai_transparency_acknowledgement
    FOR EACH ROW EXECUTE FUNCTION enforce_evidence_append_only();

-- RLS — tenant isolation (mirrors the 0003 evidence tables).
ALTER TABLE ai_transparency_acknowledgement ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ai_transparency_acknowledgement
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- Grants (defensive/idempotent — 9999 also covers these; explicit here so an
-- incremental apply after 9999 still grants app traffic access).
-- -----------------------------------------------------------------------------

GRANT SELECT, INSERT ON ai_transparency_acknowledgement TO chora_governance_app_rw;
GRANT SELECT           ON ai_transparency_acknowledgement TO chora_governance_app_ro;
GRANT SELECT, INSERT, UPDATE, DELETE ON transparency_disclosure_version TO chora_governance_app_rw;
GRANT SELECT           ON transparency_disclosure_version TO chora_governance_app_ro;

-- -----------------------------------------------------------------------------
-- Seed — the launch disclosure version 2026-07-01 (ADR-225 §7 verbatim copy).
-- Editorial vs material re-prompt is governed by requires_reacknowledgement.
-- This first version is a fresh notice for everyone -> true.
-- -----------------------------------------------------------------------------

INSERT INTO transparency_disclosure_version
    (version, status, requires_reacknowledgement, effective_from, scope, created_by, approved_by, locales)
VALUES (
    '2026-07-01', 'active', true, '2026-07-01T00:00:00Z', 'platform',
    'governance-architect', 'dale',
    $json${
      "en": {
        "standard": {
          "notice": {
            "title": "Say hi to your Familiar ✨",
            "body": "Your Familiar is powered by AI. It dreams up hints, questions, and encouragement made just for you — so learning feels like an adventure, not a checklist.\n\nTwo honest things before we start:\n\n• AI can get things wrong. If something looks off, trust your instincts and double-check it — especially before a graded test or exam.\n• You're always in control. Your Familiar learns from how you learn, and you can see — and steer — what it remembers about you, any time.",
            "action": "Got it — let's explore"
          },
          "badge": {
            "label": "✨ AI companion",
            "tooltip": "Powered by AI. Familiars are brilliant but not perfect — double-check anything important."
          },
          "inlineLabels": {
            "aiGenerated": { "label": "AI-generated", "tooltip": "Made by AI for your practice. Spotted something off? Tell us — it helps everyone learn better." },
            "aiAssisted":  { "label": "AI-assisted", "tooltip": "Drafted by AI and reviewed by a person." },
            "doseHeader":  { "label": "✨ Picked for you by AI", "tooltip": "Today's set was chosen and made by AI to match where you are. Questions can be wrong — check important facts." }
          }
        },
        "minor": {
          "notice": {
            "title": "Meet your Familiar ✨",
            "body": "Your Familiar is a friendly AI helper. It makes hints, questions, and cheers just for you!\n\n• Sometimes AI gets things wrong. If something looks funny, ask a teacher or grown-up, and always check important answers yourself.\n• You're the boss. Your Familiar remembers what helps you learn, and you can change that whenever you want.",
            "action": "Okay, let's go!"
          },
          "badge": {
            "label": "✨ AI companion",
            "tooltip": "Your Familiar is an AI helper. It can make mistakes — check important things."
          },
          "inlineLabels": {
            "aiGenerated": { "label": "Made by AI", "tooltip": "An AI made this for you to practise." },
            "aiAssisted":  { "label": "AI + a person", "tooltip": "An AI made this and a person checked it." },
            "doseHeader":  { "label": "✨ Picked for you by AI", "tooltip": "An AI chose today's set for you. It can be wrong — check important things." }
          }
        }
      }
    }$json$::jsonb
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
