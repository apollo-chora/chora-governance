// policy_repository.go — pgx-backed implementation of policy.Repository.
//
// Schema: policy_rules (migration 0006_policy.sql).
// Unlike audit_log / accountability_evidence / model_card_registry which are
// APPEND-ONLY (trigger-rejected UPDATE/DELETE), PolicyRule is mutable state —
// admins create/update/deactivate rules from H+ governance console. The
// underlying table allows UPDATE; Save uses ON CONFLICT (rule_id) DO UPDATE
// for upsert semantics.
//
// Tenant scoping:
//   - tenant_id IS NULL → global rule, applicable to every tenant
//   - tenant_id != NULL → tenant-scoped rule, applicable only to that tenant
//
// FindApplicable returns the union (active tenant rules + active global rules).
// Mirrors the InMemoryRepository at internal/domain/policy/policy.go:291-304.
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

// PolicyRepository is the pgx-backed implementation of policy.Repository.
type PolicyRepository struct {
	q Querier
	// tx is the tenant-scoped transaction runner, present when the injected
	// Querier also satisfies TenantTxQuerier (PgxPoolQuerier does). Writes go
	// through it; reads stay on the base surface, whose RLS USING clause
	// already admits platform-global rows.
	tx TenantTxQuerier
}

// NewPolicyRepository constructs a PolicyRepository backed by the supplied
// Querier (typically PgxPoolQuerier).
func NewPolicyRepository(q Querier) *PolicyRepository {
	r := &PolicyRepository{q: q}
	if tx, ok := q.(TenantTxQuerier); ok {
		r.tx = tx
	}
	return r
}

// Save persists r as an upsert keyed on rule_id. Allows mutation of name,
// conditions, effect, active, and version — created_at is preserved on
// conflict, updated_at is touched by the trg_policy_rules_updated_at trigger.
//
// Global rules (TenantID == "") store tenant_id as NULL via NULLIF(”,”).
func (r *PolicyRepository) Save(ctx context.Context, rule *policy.Rule) error {
	if rule == nil {
		return errors.New("policy.Save: nil rule")
	}
	condJSON, err := json.Marshal(rule.Conditions)
	if err != nil {
		return fmt.Errorf("policy.Save: marshal conditions: %w", err)
	}
	effect := effectFromMode(rule.EnforcementMode)
	active := rule.Status == policy.StatusActive

	const q = `INSERT INTO policy_rules (
		rule_id, tenant_id, name, description, condition_expression,
		effect, active, version, created_at, updated_at
	) VALUES (
		$1::uuid, NULLIF($2,'')::uuid, $3, $4, $5::jsonb,
		$6::policy_effect, $7, $8, $9, $10
	)
	ON CONFLICT (rule_id) DO UPDATE SET
		tenant_id = EXCLUDED.tenant_id,
		name = EXCLUDED.name,
		description = EXCLUDED.description,
		condition_expression = EXCLUDED.condition_expression,
		effect = EXCLUDED.effect,
		active = EXCLUDED.active,
		version = EXCLUDED.version,
		updated_at = EXCLUDED.updated_at`

	args := []any{
		rule.RuleID, rule.TenantID, rule.Name, "", // description blank for now
		string(condJSON),
		string(effect), active, rule.Version,
		rule.CreatedAt, rule.UpdatedAt,
	}

	// policy_rules is RLS-protected by
	//   FOR ALL USING (tenant_id IS NULL OR tenant_id = current_setting('chora.tenant_id', true)::uuid)
	// and its with_check is NULL, so PostgreSQL applies that USING as the WITH
	// CHECK on INSERT. A bare-pool write of a TENANT-SCOPED rule therefore
	// evaluates current_setting to NULL and raises 42501. It never fired only
	// because policy_rules has held zero rows in production, the same way
	// audit_log carried this latent for months (requirement G5, 2026-08-14).
	//
	// A platform-global rule is scoped to the canonical nil tenant rather than
	// left unscoped, so every write on this path is uniformly tenant-scoped.
	if r.tx != nil {
		if err := r.tx.WithTenantTx(ctx, NormalizeTenantForRLS(rule.TenantID),
			func(ctx context.Context, tx TenantScopedQuerier) error {
				return tx.Exec(ctx, q, args...)
			}); err != nil {
			return fmt.Errorf("policy.Save: %w", err)
		}
		return nil
	}
	if err := r.q.Exec(ctx, q, args...); err != nil {
		return fmt.Errorf("policy.Save: %w", err)
	}
	return nil
}

// Get returns a single rule by id. Returns policy.ErrNotFound on miss.
func (r *PolicyRepository) Get(ctx context.Context, ruleID string) (*policy.Rule, error) {
	const q = `SELECT rule_id::TEXT, COALESCE(tenant_id::TEXT,''), name,
		description, condition_expression::TEXT, effect::TEXT,
		active, version, created_at, updated_at
		FROM policy_rules
		WHERE rule_id = $1::uuid`
	row := r.q.QueryRow(ctx, q, ruleID)
	return scanRule(row)
}

// List returns rules optionally filtered by tenant.
func (r *PolicyRepository) List(ctx context.Context, f policy.ListFilter) ([]*policy.Rule, error) {
	q := `SELECT rule_id::TEXT, COALESCE(tenant_id::TEXT,''), name,
		description, condition_expression::TEXT, effect::TEXT,
		active, version, created_at, updated_at
		FROM policy_rules
		WHERE 1=1`
	args := []any{}
	idx := 0
	addArg := func(v any) string {
		idx++
		args = append(args, v)
		return fmt.Sprintf("$%d", idx)
	}
	if f.TenantID != "" {
		q += " AND tenant_id = " + addArg(f.TenantID) + "::uuid"
	}
	q += " ORDER BY updated_at DESC, rule_id ASC"
	if f.Limit > 0 {
		q += " LIMIT " + addArg(f.Limit)
	}
	if f.Offset > 0 {
		q += " OFFSET " + addArg(f.Offset)
	}

	rows, err := r.q.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("policy.List: %w", err)
	}
	defer rows.Close()

	out := []*policy.Rule{}
	for rows.Next() {
		rule, err := scanRuleFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("policy.List: %w", err)
		}
		out = append(out, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy.List: iter: %w", err)
	}
	return out, nil
}

// FindApplicable returns active rules for the given tenant plus all active
// global rules. Mirrors the InMemoryRepository behaviour.
func (r *PolicyRepository) FindApplicable(ctx context.Context, tenantID string) ([]*policy.Rule, error) {
	const q = `SELECT rule_id::TEXT, COALESCE(tenant_id::TEXT,''), name,
		description, condition_expression::TEXT, effect::TEXT,
		active, version, created_at, updated_at
		FROM policy_rules
		WHERE active = TRUE
		  AND (tenant_id IS NULL OR tenant_id = $1::uuid)
		ORDER BY updated_at DESC, rule_id ASC`

	rows, err := r.q.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("policy.FindApplicable: %w", err)
	}
	defer rows.Close()

	out := []*policy.Rule{}
	for rows.Next() {
		rule, err := scanRuleFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("policy.FindApplicable: %w", err)
		}
		out = append(out, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy.FindApplicable: iter: %w", err)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// scan helpers
// -----------------------------------------------------------------------------

// scanRule scans a single row into a *policy.Rule. Returns policy.ErrNotFound
// when the underlying error is pg.ErrNoRows.
func scanRule(row Row) (*policy.Rule, error) {
	var (
		ruleID, tenantID, name, description, condJSON, effect string
		active                                                bool
		version                                               int
		createdAt, updatedAt                                  time.Time
	)
	err := row.Scan(
		&ruleID, &tenantID, &name, &description, &condJSON, &effect,
		&active, &version, &createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, policy.ErrNotFound
		}
		return nil, fmt.Errorf("policy: scan: %w", err)
	}
	return buildRule(ruleID, tenantID, name, description, condJSON, effect, active, version, createdAt, updatedAt)
}

// scanRuleFromRows scans the current cursor position of Rows into a *policy.Rule.
func scanRuleFromRows(rows Rows) (*policy.Rule, error) {
	var (
		ruleID, tenantID, name, description, condJSON, effect string
		active                                                bool
		version                                               int
		createdAt, updatedAt                                  time.Time
	)
	if err := rows.Scan(
		&ruleID, &tenantID, &name, &description, &condJSON, &effect,
		&active, &version, &createdAt, &updatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return buildRule(ruleID, tenantID, name, description, condJSON, effect, active, version, createdAt, updatedAt)
}

// buildRule assembles a *policy.Rule from scanned scalar columns.
func buildRule(ruleID, tenantID, _name, _description, condJSON, effect string, active bool, version int, createdAt, updatedAt time.Time) (*policy.Rule, error) {
	conds := []policy.Condition{}
	if condJSON != "" {
		if err := json.Unmarshal([]byte(condJSON), &conds); err != nil {
			return nil, fmt.Errorf("decode conditions: %w", err)
		}
	}
	status := policy.StatusActive
	if !active {
		status = policy.StatusInactive
	}
	return &policy.Rule{
		RuleID:          ruleID,
		Name:            _name,
		TenantID:        tenantID,
		EnforcementMode: modeFromEffect(effect),
		Conditions:      conds,
		Version:         version,
		Status:          status,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}, nil
}

// effectFromMode collapses the 3-mode domain enforcement (allow/warn/deny)
// onto the binary table-level effect (permitted/denied). Both allow and warn
// map to permitted; the rich mode lives in the domain layer alongside the
// condition AST.
func effectFromMode(m policy.EnforcementMode) string {
	if m == policy.ModeDeny {
		return "denied"
	}
	return "permitted"
}

// modeFromEffect is the inverse — table effect → domain mode. Without a
// secondary column we cannot distinguish allow vs warn on read, so we round-
// trip warn to allow. Operators wanting warn semantics must persist that bit
// in the condition_expression metadata.
func modeFromEffect(e string) policy.EnforcementMode {
	if e == "denied" {
		return policy.ModeDeny
	}
	return policy.ModeAllow
}

// Compile-time check.
var _ policy.Repository = (*PolicyRepository)(nil)
