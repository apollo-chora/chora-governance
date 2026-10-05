// Package policy is the PolicyRule aggregate of the Governance domain.
//
// PolicyRule declares a Gatekeeper rule scoped to either a specific tenant
// or globally (TenantID empty). Rules carry an enforcement_mode (allow/warn/
// deny) and a list of declarative conditions evaluated as a logical AND.
//
// Per CLAUDE.md §1 the Governance domain owns the Gatekeeper. PolicyRule is
// a domain aggregate root: all mutations go through methods on Rule.
//
// Hexagonal: this package is dependency-free w.r.t. infrastructure. Adapters
// (in-memory, future Cloud SQL) implement the Repository port.
package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// EnforcementMode
// -----------------------------------------------------------------------------

// EnforcementMode is the rule's verdict when its conditions match.
type EnforcementMode string

const (
	ModeAllow EnforcementMode = "allow"
	ModeWarn  EnforcementMode = "warn"
	ModeDeny  EnforcementMode = "deny"
)

// Valid reports whether m is one of allow/warn/deny.
func (m EnforcementMode) Valid() bool {
	switch m {
	case ModeAllow, ModeWarn, ModeDeny:
		return true
	}
	return false
}

// Status is the lifecycle status of a Rule.
type Status string

const (
	StatusActive   Status = "active"
	StatusInactive Status = "inactive"
)

// Valid reports whether s is one of active/inactive.
func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusInactive:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// Condition — declarative DSL stub
// -----------------------------------------------------------------------------

// Op is a condition operator.
type Op string

const (
	OpEquals    Op = "equals"
	OpNotEquals Op = "not_equals"
	OpIn        Op = "in"
)

// Valid reports whether o is a known operator.
func (o Op) Valid() bool {
	switch o {
	case OpEquals, OpNotEquals, OpIn:
		return true
	}
	return false
}

// Condition is one declarative test against an evaluation context map.
type Condition struct {
	Field string `json:"field"`
	Op    Op     `json:"op"`
	Value any    `json:"value"`
}

// matches evaluates this condition against the supplied context.
func (c Condition) matches(ctx map[string]any) bool {
	got, ok := ctx[c.Field]
	if !ok {
		return false
	}
	switch c.Op {
	case OpEquals:
		return equalsAny(got, c.Value)
	case OpNotEquals:
		return !equalsAny(got, c.Value)
	case OpIn:
		// Value should be a slice; check membership.
		arr, ok := c.Value.([]any)
		if !ok {
			return false
		}
		for _, v := range arr {
			if equalsAny(got, v) {
				return true
			}
		}
		return false
	}
	return false
}

// equalsAny compares two interface{} values for equality. Strings, numbers,
// and bools compare by direct equality; everything else falls back to
// fmt.Sprintf string equality (sufficient for the skeleton's DSL).
func equalsAny(a, b any) bool {
	if a == b {
		return true
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// -----------------------------------------------------------------------------
// Rule aggregate root
// -----------------------------------------------------------------------------

// Rule is the PolicyRule aggregate root.
type Rule struct {
	RuleID          string          `json:"rule_id"`
	Name            string          `json:"name"`
	TenantID        string          `json:"tenant_id"` // empty = global scope
	EnforcementMode EnforcementMode `json:"enforcement_mode"`
	Conditions      []Condition     `json:"conditions"`
	Version         int             `json:"version"`
	Status          Status          `json:"status"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// NewParams is the constructor input for New.
type NewParams struct {
	Name            string
	TenantID        string // empty = global
	EnforcementMode EnforcementMode
	Conditions      []Condition
}

// New constructs a fresh active Rule. Returns an error if inputs violate
// invariants (empty name, invalid mode, no conditions, invalid op).
func New(p NewParams) (*Rule, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	if !p.EnforcementMode.Valid() {
		return nil, fmt.Errorf("invalid enforcement_mode: %q", string(p.EnforcementMode))
	}
	if len(p.Conditions) == 0 {
		return nil, errors.New("conditions cannot be empty")
	}
	for i, c := range p.Conditions {
		if strings.TrimSpace(c.Field) == "" {
			return nil, fmt.Errorf("condition[%d].field is required", i)
		}
		if !c.Op.Valid() {
			return nil, fmt.Errorf("condition[%d].op invalid: %q", i, string(c.Op))
		}
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}

	conds := append([]Condition(nil), p.Conditions...)

	now := time.Now().UTC()
	return &Rule{
		RuleID:          id.String(),
		Name:            name,
		TenantID:        strings.TrimSpace(p.TenantID),
		EnforcementMode: p.EnforcementMode,
		Conditions:      conds,
		Version:         1,
		Status:          StatusActive,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// IsGlobal reports whether the rule has global (cross-tenant) scope.
func (r *Rule) IsGlobal() bool { return r.TenantID == "" }

// Matches reports whether all conditions pass against the supplied context.
// AND semantics: every condition must match.
func (r *Rule) Matches(ctx map[string]any) bool {
	for _, c := range r.Conditions {
		if !c.matches(ctx) {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Repository port + in-memory implementation
// -----------------------------------------------------------------------------

// ErrNotFound is the canonical sentinel for a missing rule.
var ErrNotFound = errors.New("policy rule not found")

// Repository is the PolicyRule persistence port.
type Repository interface {
	Save(ctx context.Context, r *Rule) error
	Get(ctx context.Context, ruleID string) (*Rule, error)
	List(ctx context.Context, filter ListFilter) ([]*Rule, error)
	// FindApplicable returns rules that apply to the given tenant: tenant-
	// scoped rules whose TenantID matches, plus all global rules. Inactive
	// rules are excluded. Used by the gatekeeper evaluator.
	FindApplicable(ctx context.Context, tenantID string) ([]*Rule, error)
}

// ListFilter is the query filter for List.
type ListFilter struct {
	TenantID string // empty = no tenant filter (returns all)
	Limit    int
	Offset   int
}

// InMemoryRepository is the dev/test implementation of Repository.
type InMemoryRepository struct {
	mu    sync.RWMutex
	rules map[string]*Rule
}

// NewInMemoryRepository constructs an empty in-memory repo.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{rules: make(map[string]*Rule)}
}

// Save persists r (upsert by RuleID).
func (m *InMemoryRepository) Save(_ context.Context, r *Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := cloneRule(r)
	m.rules[r.RuleID] = clone
	return nil
}

// Get returns the rule by ID or ErrNotFound.
func (m *InMemoryRepository) Get(_ context.Context, id string) (*Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rules[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneRule(r), nil
}

// List returns rules optionally filtered by tenant.
func (m *InMemoryRepository) List(_ context.Context, f ListFilter) ([]*Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Rule, 0, len(m.rules))
	for _, r := range m.rules {
		if f.TenantID != "" && r.TenantID != f.TenantID {
			continue
		}
		out = append(out, cloneRule(r))
	}
	if f.Offset > 0 && f.Offset < len(out) {
		out = out[f.Offset:]
	} else if f.Offset >= len(out) {
		out = nil
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

// FindApplicable returns active rules for tenantID + active global rules.
func (m *InMemoryRepository) FindApplicable(_ context.Context, tenantID string) ([]*Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Rule, 0, len(m.rules))
	for _, r := range m.rules {
		if r.Status != StatusActive {
			continue
		}
		if r.IsGlobal() || r.TenantID == tenantID {
			out = append(out, cloneRule(r))
		}
	}
	return out, nil
}

func cloneRule(r *Rule) *Rule {
	c := *r
	c.Conditions = append([]Condition(nil), r.Conditions...)
	return &c
}
