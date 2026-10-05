// priority_test.go — unit tests for the rubric item Priority (P1/P2/P3)
// categorisation that drives the O+ dimensions traffic-light + per-item badges.
// Per [[tdd-blanket]] 85% domain coverage gate.
package rubric_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
)

func TestPriority_Valid(t *testing.T) {
	t.Parallel()
	for _, p := range []rubric.Priority{rubric.PriorityP1, rubric.PriorityP2, rubric.PriorityP3} {
		if !p.Valid() {
			t.Errorf("%q.Valid() = false; want true", p)
		}
	}
	for _, p := range []string{"", "P0", "p1", "high", "P4"} {
		if rubric.Priority(p).Valid() {
			t.Errorf("%q.Valid() = true; want false", p)
		}
	}
}

// Priority propagates from the YAML ConfigItem through Resolve() onto the
// resolved RubricItem for BOTH static and auto derivation modes — the FE badge
// + the gateway traffic-light rule depend on it.
func TestResolve_PropagatesPriority(t *testing.T) {
	t.Parallel()
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "audit", Title: "Audit Trail", EvidenceSource: "Cloud Trace",
						DerivationMode: rubric.ModeAuto, AutoQueryKey: "audit_trail_coverage",
						Priority: rubric.PriorityP1},
					{ID: "raci", Title: "RACI Matrix", EvidenceSource: "doc",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPartial,
						Priority: rubric.PriorityP2},
					{ID: "no_prio", Title: "Unscored", EvidenceSource: "doc",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusFail},
				},
			},
		},
	}
	repo := evidence.NewInMemoryRepository()
	res, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := res.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("len(items) = %d; want 3", len(items))
	}
	if items[0].Priority != rubric.PriorityP1 {
		t.Errorf("auto item priority = %q; want P1", items[0].Priority)
	}
	if items[1].Priority != rubric.PriorityP2 {
		t.Errorf("static item priority = %q; want P2", items[1].Priority)
	}
	if items[2].Priority != "" {
		t.Errorf("unscored item priority = %q; want empty", items[2].Priority)
	}
}

// A static item's configured EvidenceURL (a real repo .md deep-link) propagates
// onto the resolved RubricItem so the FE renders a "View evidence ↗" link.
func TestResolve_StaticEvidenceURLPropagates(t *testing.T) {
	t.Parallel()
	const url = "https://github.com/apollo-chora/chora-governance/blob/main/docs/governance/agentic-ai-raci.md"
	cfg := rubric.Config{
		Dimensions: map[string]rubric.DimensionConfig{
			"accountability": {
				Items: []rubric.ConfigItem{
					{ID: "raci", Title: "RACI Matrix", EvidenceSource: "doc",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusPass,
						Priority: rubric.PriorityP2, EvidenceURL: url},
					{ID: "nolink", Title: "No link", EvidenceSource: "doc",
						DerivationMode: rubric.ModeStatic, StaticStatus: rubric.StatusFail},
				},
			},
		},
	}
	repo := evidence.NewInMemoryRepository()
	res, err := rubric.NewResolver(cfg, repo)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	items, err := res.Resolve(context.Background(), "tenant-1", "accountability")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if items[0].EvidenceSourceURL != url {
		t.Errorf("static evidence url = %q; want %q", items[0].EvidenceSourceURL, url)
	}
	if items[1].EvidenceSourceURL != "" {
		t.Errorf("unlinked item url = %q; want empty", items[1].EvidenceSourceURL)
	}
}
