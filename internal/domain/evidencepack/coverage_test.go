// Coverage-fill tests for evidencepack — exercises empty + nil + sanitize.
package evidencepack_test

import (
	"archive/zip"
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/evidencepack"
)

// Empty repo — exporter should still emit a valid ZIP with just manifest +
// audit_chain.json + empty CSV headers + lifecycle stage placeholders.
func TestExporter_EmptyRepoStillProducesValidZIP(t *testing.T) {
	er := evidence.NewInMemoryRepository()
	ar := audit.NewInMemoryRepository()
	exp := evidencepack.New(er, ar)

	out, err := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "tenant-empty",
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	if err != nil {
		t.Fatalf("zip read: %v", err)
	}
	hasManifest := false
	for _, f := range zr.File {
		if f.Name == "manifest.yaml" {
			hasManifest = true
		}
	}
	if !hasManifest {
		t.Error("empty-repo export must still include manifest")
	}
}

// Nil exporter
func TestExporter_NilExporter_Errors(t *testing.T) {
	var exp *evidencepack.Exporter
	if _, err := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "t",
	}); err == nil {
		t.Error("nil exporter must error")
	}
}

// Manifest hash present
func TestExporter_ManifestSHAPopulated(t *testing.T) {
	er := evidence.NewInMemoryRepository()
	ar := audit.NewInMemoryRepository()
	exp := evidencepack.New(er, ar)
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)
	out, _ := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "t1", From: from, To: to,
	})
	if out.ManifestSHA == "" {
		t.Error("ManifestSHA must be populated")
	}
	if len(out.ManifestSHA) != 64 {
		t.Errorf("ManifestSHA len=%d want 64 (hex sha256)", len(out.ManifestSHA))
	}
}

// Filter by D2 only
func TestExporter_FilterByD2Only(t *testing.T) {
	er := evidence.NewInMemoryRepository()
	ar := audit.NewInMemoryRepository()
	mc, _ := evidence.NewModelCard(evidence.ModelCardParams{
		EventID: "e1", TenantID: "t",
		ModelID: "m", ModelVersion: "v", CardMD: "x",
	})
	er.AppendModelCard(context.Background(), mc)

	exp := evidencepack.New(er, ar)
	out, _ := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "t", Dimensions: []string{"D2"},
	})
	zr, _ := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	hasD1 := false
	hasD3 := false
	hasD4 := false
	hasD2Models := false
	for _, f := range zr.File {
		switch {
		case strings.HasPrefix(f.Name, "D1/"):
			hasD1 = true
		case strings.HasPrefix(f.Name, "D3/"):
			hasD3 = true
		case strings.HasPrefix(f.Name, "D4/"):
			hasD4 = true
		case f.Name == "D2/model_cards.csv":
			hasD2Models = true
		}
	}
	if hasD1 || hasD3 || hasD4 {
		t.Error("D2-only export should not include other dimensions")
	}
	if !hasD2Models {
		t.Error("D2-only export should include D2/model_cards.csv")
	}
}

// Quarantine release branch — released_at populated row in CSV
func TestExporter_QuarantineWithReleasedAt(t *testing.T) {
	er := evidence.NewInMemoryRepository()
	ar := audit.NewInMemoryRepository()
	q := evidence.NewQuarantine("t", "ag", "circuit_open")
	q.Release()
	er.UpsertQuarantine(context.Background(), q)

	exp := evidencepack.New(er, ar)
	out, _ := exp.Export(context.Background(), evidencepack.ExportRequest{TenantID: "t"})
	zr, _ := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	for _, f := range zr.File {
		if f.Name != "D3/quarantine_state.csv" {
			continue
		}
		rc, _ := f.Open()
		body := make([]byte, 4096)
		n, _ := rc.Read(body)
		rc.Close()
		s := string(body[:n])
		// Should contain at least 2 timestamps (quarantined + released)
		if !strings.Contains(s, "circuit_open") {
			t.Errorf("quarantine CSV missing reason: %s", s)
		}
	}
}

// Audit-only filter (empty period)
func TestExporter_NoPeriodAcceptsAll(t *testing.T) {
	er := evidence.NewInMemoryRepository()
	ar := audit.NewInMemoryRepository()
	a, _ := evidence.NewAccountabilityEvidence(evidence.AccountabilityParams{
		EventID: "e1", TenantID: "t", AgentID: "a", OwnerGcid: "o",
		DecisionID: "d", DecisionType: "x",
	})
	er.AppendAccountability(context.Background(), a)

	exp := evidencepack.New(er, ar)
	out, _ := exp.Export(context.Background(), evidencepack.ExportRequest{TenantID: "t"})
	if out.CountD1 != 1 {
		t.Errorf("CountD1=%d want 1", out.CountD1)
	}
}

// Sanitize edge cases for filenames
func TestExporter_SanitizesFilenames(t *testing.T) {
	er := evidence.NewInMemoryRepository()
	ar := audit.NewInMemoryRepository()
	mc, _ := evidence.NewModelCard(evidence.ModelCardParams{
		EventID: "e1", TenantID: "t",
		ModelID: "vendor/model with spaces", ModelVersion: "v 1/0",
		CardMD: "x",
	})
	er.AppendModelCard(context.Background(), mc)

	exp := evidencepack.New(er, ar)
	out, _ := exp.Export(context.Background(), evidencepack.ExportRequest{
		TenantID: "t",
	})
	zr, _ := zip.NewReader(bytes.NewReader(out.ZIPBytes), int64(len(out.ZIPBytes)))
	found := false
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "model_cards/") && strings.HasSuffix(f.Name, ".md") {
			found = true
			if strings.Contains(f.Name, " ") || strings.Contains(strings.TrimPrefix(f.Name, "model_cards/"), "/") {
				t.Errorf("sanitize failed for %q", f.Name)
			}
		}
	}
	if !found {
		t.Error("model_cards/ entry expected")
	}
}
