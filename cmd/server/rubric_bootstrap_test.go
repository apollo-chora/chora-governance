// rubric_bootstrap_test.go — contract guard for config/imda_rubric.yaml.
//
// The real rubric YAML is loaded at boot (loadRubricConfig) and drives the O+
// dimensions traffic-light + per-item priority badges. A malformed file only
// surfaces as a runtime 503, so this test locks the contract in CI: 31 items
// across 4 canonical dimensions, every item a valid P1/P2/P3 priority, static
// items a valid status, and every evidence_url an in-repo github deep-link.
package main

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
)

const repoBlobPrefix = "https://github.com/apollo-chora/chora-governance/blob/"

func TestRubricConfig_RealFile_Contract(t *testing.T) {
	cfg, err := loadRubricConfig()
	if err != nil {
		t.Fatalf("loadRubricConfig: %v", err)
	}

	wantDims := []string{
		"accountability",
		"transparency",
		"safety_and_robustness",
		"fairness_and_human_oversight",
	}
	for _, d := range wantDims {
		if _, ok := cfg.Dimensions[d]; !ok {
			t.Errorf("missing dimension %q", d)
		}
	}
	if len(cfg.Dimensions) != len(wantDims) {
		t.Errorf("dimensions = %d; want %d", len(cfg.Dimensions), len(wantDims))
	}

	total := 0
	for dim, dc := range cfg.Dimensions {
		for _, it := range dc.Items {
			total++
			// Every item carries a valid remediation priority — the
			// traffic-light + badge depend on it.
			if !it.Priority.Valid() {
				t.Errorf("%s/%s: priority %q invalid; want P1|P2|P3", dim, it.ID, it.Priority)
			}
			switch it.DerivationMode {
			case rubric.ModeStatic:
				if !it.StaticStatus.Valid() {
					t.Errorf("%s/%s: static item with invalid static_status %q", dim, it.ID, it.StaticStatus)
				}
			case rubric.ModeAuto:
				if strings.TrimSpace(it.AutoQueryKey) == "" {
					t.Errorf("%s/%s: auto item with empty auto_query_key", dim, it.ID)
				}
			default:
				t.Errorf("%s/%s: invalid derivation_mode %q", dim, it.ID, it.DerivationMode)
			}
			// Evidence deep-links must point inside the repo (no external /
			// fabricated URLs).
			if it.EvidenceURL != "" && !strings.HasPrefix(it.EvidenceURL, repoBlobPrefix) {
				t.Errorf("%s/%s: evidence_url %q not a repo blob link", dim, it.ID, it.EvidenceURL)
			}
		}
	}
	if total != 31 {
		t.Errorf("total rubric items = %d; want 31", total)
	}
}
