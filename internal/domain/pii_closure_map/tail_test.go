// tail_test.go — coverage tail: Parse's yaml-unmarshal + invalid-map error
// branches and Register's blank-domain / blank-tenant guards.
package pii_closure_map_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/pii_closure_map"
)

func TestParse_MalformedYAMLErrors(t *testing.T) {
	t.Parallel()
	if _, err := pii_closure_map.Parse([]byte("not: [valid")); err == nil {
		t.Error("malformed YAML should fail Parse")
	}
}

func TestParse_InvalidContentErrors(t *testing.T) {
	t.Parallel()
	// well-formed YAML but the map is invalid (missing domain)
	if _, err := pii_closure_map.Parse([]byte("version: \"1\"")); err == nil {
		t.Error("missing domain should fail Parse")
	}
}

func TestRegister_BlankDomainAndTenant(t *testing.T) {
	t.Parallel()
	repo := pii_closure_map.NewInMemoryRepository()
	ctx := context.Background()
	validYAML := []byte("domain: chora_creation\nversion: \"1\"\n")

	if _, err := repo.Register(ctx, pii_closure_map.RegisterParams{
		Domain: "", TenantID: "t1", Gcid: "g1", YAML: validYAML,
	}); err == nil {
		t.Error("blank domain should error")
	}
	if _, err := repo.Register(ctx, pii_closure_map.RegisterParams{
		Domain: "chora_creation", TenantID: "", Gcid: "g1", YAML: validYAML,
	}); err == nil {
		t.Error("blank tenant should error")
	}
}
