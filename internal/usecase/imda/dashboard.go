// Package imda is the usecase layer wrapping the IMDA Dashboard derivation
// per Phase B of the O+ hydration plan.
//
// Per anchoring decision #3 (hybrid rubric resolver) the dashboard %
// derivation is a function of:
//
//  1. The existing imda.Repository (assessor-recorded scores via
//     RecordAssessment — manual override path)
//  2. The rubric resolver (PassRate over the per-dimension rubric items,
//     where auto items query the evidence aggregates populated by the
//     canonical projector + observability subscriber)
//
// Behavioural contract — GetIMDADashboard:
//
//   - If a tenant has recorded assessments for a dimension, those scores
//     take precedence (preserves the manual-override semantics of
//     RecordAssessment per existing chora-governance contract).
//   - If a dimension has no recorded assessment for the tenant, the score
//     is derived from rubric pass-rate × 100 (PASS=1.0, PARTIAL=0.5,
//     FAIL=0.0; averaged across all items in the dimension).
//
// This is the load-bearing wiring that takes the dashboard from "manual
// assessment only" to "live evidence-driven posture" — without breaking the
// existing assessor-recording flow.
//
// Per [[feedback-no-stubs-real-wiring]]: connects through the existing
// imda.Repository + evidence.Repository interfaces. No in-memory stubs.
package imda

import (
	"context"
	"errors"
	"fmt"
	"strings"

	domainimda "github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
)

// DashboardItem is one per-dimension row returned by GetIMDADashboard.
// Mirrors the domain Assessment + adds the rubric drilldown for the FE
// (chora-web O+ dimensions panel).
type DashboardItem struct {
	Dimension    domainimda.Dimension `json:"dimension"`
	Score        int                  `json:"score"`  // 0..100 inclusive
	Source       string               `json:"source"` // "assessment" | "rubric"
	AssessmentID string               `json:"assessment_id,omitempty"`
	Indicators   []string             `json:"indicators,omitempty"`
	RubricItems  []rubric.RubricItem  `json:"rubric_items,omitempty"`
}

// DashboardResult groups the per-dimension items + tenant context.
type DashboardResult struct {
	TenantID   string          `json:"tenant_id"`
	Dimensions []DashboardItem `json:"dimensions"`
}

// Service wraps the existing imda.Repository + rubric resolver to produce
// the canonical Dashboard payload for the O+ surface.
type Service struct {
	imdas    domainimda.Repository
	resolver *rubric.Resolver
}

// NewService constructs the dashboard service. Returns an error if any
// dependency is nil; per [[feedback-no-stubs-real-wiring]] callers MUST
// supply the production repos.
func NewService(imdas domainimda.Repository, resolver *rubric.Resolver) (*Service, error) {
	if imdas == nil {
		return nil, errors.New("imda.NewService: imda.Repository is required")
	}
	if resolver == nil {
		return nil, errors.New("imda.NewService: rubric.Resolver is required")
	}
	return &Service{imdas: imdas, resolver: resolver}, nil
}

// GetIMDADashboard derives the IMDA dashboard for the supplied tenant.
//
// For each canonical dimension:
//   - If a recorded assessment exists (non-empty AssessmentID), the
//     assessor-supplied Score wins (manual override path stays intact).
//   - Otherwise the score is derived from rubric.Resolver.PassRate() ×
//     100, rounded to the nearest integer.
//
// The rubric_items list is always populated (regardless of override path)
// so the FE drilldown panel renders the same shape per dimension.
//
// Returns an error only on infrastructure failure (repo error); a missing
// rubric config for a given dimension degrades to an empty rubric_items
// list with the assessment-or-zero score, NOT an error — defensive so a
// partial deployment of imda_rubric.yaml doesn't 500 the dashboard.
func (s *Service) GetIMDADashboard(ctx context.Context, tenantID string) (*DashboardResult, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("imda.GetIMDADashboard: tenant_id is required")
	}
	// Step 1 — pull the latest assessments (existing manual-override path).
	assessments, err := s.imdas.Dashboard(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("imda.GetIMDADashboard: assessment lookup: %w", err)
	}
	byDimension := make(map[domainimda.Dimension]*domainimda.Assessment, 4)
	for _, a := range assessments {
		byDimension[a.Dimension] = a
	}

	// Step 2 — for each canonical dimension, build a DashboardItem mixing
	// the assessment value with the rubric resolver output.
	out := make([]DashboardItem, 0, 4)
	for _, dim := range domainimda.AllDimensions() {
		item := DashboardItem{Dimension: dim, Source: "rubric"}

		// Rubric items + pass-rate — defensive against missing config.
		items, resolveErr := s.resolver.Resolve(ctx, tenantID, string(dim))
		if resolveErr == nil {
			item.RubricItems = items
		}
		rate, rateErr := s.resolver.PassRate(ctx, tenantID, string(dim))
		if rateErr == nil {
			item.Score = int(rate*100 + 0.5) // round half-up
		}

		// Assessment override — non-empty AssessmentID means the assessor
		// recorded a real assessment (not a zero-Score placeholder).
		if a, ok := byDimension[dim]; ok && a.AssessmentID != "" {
			item.AssessmentID = a.AssessmentID
			item.Score = a.Score
			item.Indicators = append([]string(nil), a.Indicators...)
			item.Source = "assessment"
		}

		out = append(out, item)
	}
	return &DashboardResult{TenantID: tenantID, Dimensions: out}, nil
}
