// Package compliance is the ComplianceReport derived view aggregating recent
// AuditEvents + IMDADimensionAssessments for a tenant.
//
// The skeleton produces a JSON placeholder; PDF rendering is deferred. Per
// the spec, generation is on-demand for export.
package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

// Report is the ComplianceReport aggregate (a derived read view).
type Report struct {
	ReportID         string             `json:"report_id"`
	TenantID         string             `json:"tenant_id"`
	GeneratedAt      time.Time          `json:"generated_at"`
	AuditEventCount  int                `json:"audit_event_count"`
	AuditDeniedCount int                `json:"audit_denied_count"`
	IMDADashboard    []*imda.Assessment `json:"imda_dashboard"`
	RecentAudits     []*audit.Event     `json:"recent_audits"`
}

// Generator builds Reports.
type Generator struct {
	audits audit.Repository
	imdas  imda.Repository
}

// NewGenerator wires deps.
func NewGenerator(a audit.Repository, i imda.Repository) *Generator {
	return &Generator{audits: a, imdas: i}
}

// Generate produces a fresh Report for tenantID.
func (g *Generator) Generate(ctx context.Context, tenantID string) (*Report, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("tenant_id is required")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}

	events, err := g.audits.Query(ctx, audit.QueryFilter{TenantID: tenantID, Limit: 100})
	if err != nil {
		return nil, err
	}
	denied := 0
	for _, e := range events {
		if e.Decision == audit.DecisionDenied {
			denied++
		}
	}
	dash, err := g.imdas.Dashboard(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return &Report{
		ReportID:         id.String(),
		TenantID:         tenantID,
		GeneratedAt:      time.Now().UTC(),
		AuditEventCount:  len(events),
		AuditDeniedCount: denied,
		IMDADashboard:    dash,
		RecentAudits:     events,
	}, nil
}
