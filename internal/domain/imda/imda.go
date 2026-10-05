// Package imda is the IMDADimensionAssessment aggregate of the Governance
// domain.
//
// Per CLAUDE.md §1 + project_chora_governance_ai.md D18, the IMDA Model AI
// Governance Framework is the NorthStar. All 4 dimensions are built in
// parallel from launch in the O+ surface.
//
// Per ADR-141 (2026-05-08) the 4 fixed dimensions adopt the AssessorFlow
// o-plus-dashboard gold standard (IMDA MGF v2 + AI Verify Testing
// Framework principles):
//
//	D1 accountability                  — risk classification + audit trail
//	                                     (AI Verify #8 Data Governance,
//	                                     #9 Accountability)
//	D2 transparency                    — model cards + reasoning + decision logs
//	                                     (AI Verify #1 Transparency,
//	                                     #2 Explainability)
//	D3 safety_and_robustness           — guardrails + adversarial + drift
//	                                     (AI Verify #3-#6 Repeatability,
//	                                     Safety, Security, Robustness)
//	D4 fairness_and_human_oversight    — HITL + bias + autonomy levels
//	                                     (AI Verify #7 Fairness, #10 Human
//	                                     Agency, #11 Inclusive Growth)
//
// The previous v1 labels (risk_levels / operations_management /
// internal_governance / stakeholder_interaction) remain accepted as
// DEPRECATED aliases for one release via Canonicalise() — see ADR-141 §3.
//
// The Go identifier names are unchanged from the v1 era for source-stability;
// only the bound string values are reconciled to the canonical labels.
//
// Score range is 0..100 inclusive — out-of-range values are rejected.
package imda

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
// Dimension — 4 FIXED IMDA dimensions (ADR-141 canonical labels)
// -----------------------------------------------------------------------------

// Dimension is one of the 4 fixed IMDA dimensions per ADR-141.
type Dimension string

const (
	// DimensionRiskLevels is D1 (Go identifier preserved for source stability;
	// per ADR-141 it now binds to canonical "accountability").
	DimensionRiskLevels Dimension = "accountability"

	// DimensionStakeholderInteraction is D2 (Go identifier preserved for source
	// stability; per ADR-141 it now binds to canonical "transparency").
	DimensionStakeholderInteraction Dimension = "transparency"

	// DimensionInternalGovernance is D3 (Go identifier preserved for source
	// stability; per ADR-141 it now binds to canonical
	// "safety_and_robustness").
	DimensionInternalGovernance Dimension = "safety_and_robustness"

	// DimensionOperationsManagement is D4 (Go identifier preserved for source
	// stability; per ADR-141 it now binds to canonical
	// "fairness_and_human_oversight").
	DimensionOperationsManagement Dimension = "fairness_and_human_oversight"
)

// deprecatedAliases maps v1 IMDA MGF labels onto their ADR-141 canonical form.
// Kept package-private so callers go through Canonicalise(); the alias period
// ends at the next major version of the chora-governance Cloud Run service.
var deprecatedAliases = map[string]Dimension{
	"risk_levels":             DimensionRiskLevels,             // D1 → accountability
	"stakeholder_interaction": DimensionStakeholderInteraction, // D2 → transparency
	"internal_governance":     DimensionInternalGovernance,     // D3 → safety_and_robustness
	"operations_management":   DimensionOperationsManagement,   // D4 → fairness_and_human_oversight
}

// Canonicalise normalises an input string to a canonical Dimension. Per
// ADR-141 §3 it accepts both the canonical labels and the deprecated v1
// aliases, returning the canonical Dimension in either case. Unknown labels
// pass through unchanged (callers MUST follow with Valid() to reject them).
//
// Whitespace is trimmed and the input is lowercased before lookup so that
// caller-side noise (e.g. "  RISK_LEVELS ") still resolves correctly.
func Canonicalise(s string) Dimension {
	norm := strings.ToLower(strings.TrimSpace(s))
	if alias, ok := deprecatedAliases[norm]; ok {
		return alias
	}
	return Dimension(norm)
}

// Valid reports whether d is one of the 4 fixed IMDA dimensions per ADR-141.
//
// Both the canonical labels and the deprecated v1 aliases pass Valid()
// during the alias-mode period — this lets API consumers in transition
// continue to send v1 strings without rejection. New() normalises to the
// canonical form on construction, so persisted Assessments only ever carry
// canonical labels.
func (d Dimension) Valid() bool {
	switch d {
	case DimensionInternalGovernance,
		DimensionRiskLevels,
		DimensionOperationsManagement,
		DimensionStakeholderInteraction:
		return true
	}
	// Accept deprecated v1 aliases for one release per ADR-141 §3.
	if _, ok := deprecatedAliases[string(d)]; ok {
		return true
	}
	return false
}

// AllDimensions returns the 4 fixed IMDA dimensions in the canonical order
// (D1 Accountability / D2 Transparency / D3 Safety and Robustness /
// D4 Fairness and Human Oversight) matching the AssessorFlow o-plus-dashboard
// reference and the IMDA MGF v2 framework.
func AllDimensions() []Dimension {
	return []Dimension{
		DimensionRiskLevels,             // D1 accountability
		DimensionStakeholderInteraction, // D2 transparency
		DimensionInternalGovernance,     // D3 safety_and_robustness
		DimensionOperationsManagement,   // D4 fairness_and_human_oversight
	}
}

// -----------------------------------------------------------------------------
// Assessment aggregate
// -----------------------------------------------------------------------------

// Assessment is the IMDADimensionAssessment aggregate.
type Assessment struct {
	AssessmentID string    `json:"assessment_id"`
	TenantID     string    `json:"tenant_id"`
	Dimension    Dimension `json:"dimension"`
	Score        int       `json:"score"` // 0..100 inclusive
	Indicators   []string  `json:"indicators"`
	AssessedAt   time.Time `json:"assessed_at"`
	AssessorGcid string    `json:"assessor_gcid"`
}

// NewParams is the constructor input.
type NewParams struct {
	TenantID     string
	Dimension    Dimension
	Score        int
	Indicators   []string
	AssessorGcid string
}

// New constructs an Assessment. Validates inputs.
//
// Per ADR-141 §3 the dimension is normalised via Canonicalise() so that
// persisted Assessments only ever carry the canonical (gold-standard)
// labels — even if the caller supplied a deprecated v1 alias.
func New(p NewParams) (*Assessment, error) {
	if strings.TrimSpace(p.TenantID) == "" {
		return nil, errors.New("tenant_id is required")
	}
	if strings.TrimSpace(p.AssessorGcid) == "" {
		return nil, errors.New("assessor_gcid is required")
	}
	canonical := Canonicalise(string(p.Dimension))
	if !canonical.Valid() {
		return nil, fmt.Errorf("invalid dimension: %q (must be one of accountability/transparency/safety_and_robustness/fairness_and_human_oversight per ADR-141; deprecated v1 aliases risk_levels/operations_management/internal_governance/stakeholder_interaction also accepted)",
			string(p.Dimension))
	}
	if p.Score < 0 || p.Score > 100 {
		return nil, fmt.Errorf("score out of range: %d (must be 0..100)", p.Score)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}

	indicators := append([]string(nil), p.Indicators...)

	return &Assessment{
		AssessmentID: id.String(),
		TenantID:     p.TenantID,
		Dimension:    canonical,
		Score:        p.Score,
		Indicators:   indicators,
		AssessedAt:   time.Now().UTC(),
		AssessorGcid: p.AssessorGcid,
	}, nil
}

// -----------------------------------------------------------------------------
// Repository port + in-memory implementation
// -----------------------------------------------------------------------------

// ErrNotFound is the canonical sentinel for a missing assessment.
var ErrNotFound = errors.New("imda assessment not found")

// Repository is the IMDADimensionAssessment persistence port.
type Repository interface {
	Append(ctx context.Context, a *Assessment) error
	// Dashboard returns the most-recent assessment per dimension for a tenant.
	// Always returns an entry per AllDimensions() — missing dimensions get an
	// Assessment with Score=0 and AssessmentID="" as a placeholder.
	Dashboard(ctx context.Context, tenantID string) ([]*Assessment, error)
}

// InMemoryRepository is the dev/test implementation.
type InMemoryRepository struct {
	mu          sync.RWMutex
	assessments []*Assessment
}

// NewInMemoryRepository constructs an empty in-memory repo.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{}
}

// Append stores a.
func (m *InMemoryRepository) Append(_ context.Context, a *Assessment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := *a
	clone.Indicators = append([]string(nil), a.Indicators...)
	m.assessments = append(m.assessments, &clone)
	return nil
}

// Dashboard returns the latest assessment per dimension for a tenant. If a
// dimension has never been assessed for the tenant, a zero-Score placeholder
// is returned (so consumers always see all 4 dimensions).
//
// Tie-break: when two assessments for the same dimension share an identical
// AssessedAt timestamp (sub-microsecond appends are common in test fixtures
// and in production under rapid evaluator emission), the LATER-INSERTED
// assessment wins. The contract callers expect is "latest per dimension
// reflects insertion order under tied timestamps" — i.e. last write wins.
// Iteration over the append-only slice in order achieves this with a
// non-strict After() comparison.
func (m *InMemoryRepository) Dashboard(_ context.Context, tenantID string) ([]*Assessment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	latest := make(map[Dimension]*Assessment)
	for _, a := range m.assessments {
		if a.TenantID != tenantID {
			continue
		}
		prev, ok := latest[a.Dimension]
		// Use !Before (i.e. After OR Equal) instead of After so that ties
		// resolve in favour of the later-inserted assessment. m.assessments
		// is append-only, so iteration order == insertion order, and the
		// final tied entry overwrites earlier ones.
		if !ok || !a.AssessedAt.Before(prev.AssessedAt) {
			clone := *a
			clone.Indicators = append([]string(nil), a.Indicators...)
			latest[a.Dimension] = &clone
		}
	}
	out := make([]*Assessment, 0, 4)
	for _, d := range AllDimensions() {
		if a, ok := latest[d]; ok {
			out = append(out, a)
		} else {
			out = append(out, &Assessment{
				TenantID:  tenantID,
				Dimension: d,
				Score:     0,
			})
		}
	}
	return out, nil
}
