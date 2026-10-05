// Package pii_closure_map_test — invariants for the PII Closure Map registry.
//
// Per .claude/rules/ddd-enforcement.md (Account Closure section): each domain
// owns a PII_Closure_Map.yaml declaring fields-to-tokenize, retention rules,
// and on-creator-closure behaviour. The Governance service registers these
// maps centrally for federated saga visibility.
package pii_closure_map_test

import (
	"context"
	"testing"

	piimap "github.com/apollo-chora/chora-governance/internal/domain/pii_closure_map"
)

const (
	tenantA = "01970000-0000-7000-8000-000000000001"
	gcidA   = "01970000-0000-7000-9000-000000000001"
)

const minimalYAML = `
domain: creation
schema_version: 1
fields:
  - name: author_email
    pii_class: pii_direct
    action: tokenize
  - name: profile_bio
    pii_class: pii_indirect
    action: crypto_shred
  - name: created_at
    pii_class: non_pii
    action: retain
on_creator_closure: anonymize_attribution
`

const malformedYAML = `not yaml: : ::`

const missingFieldsYAML = `
domain: ""
schema_version: 0
`

// -----------------------------------------------------------------------------
// Validate
// -----------------------------------------------------------------------------

func TestValidate_AcceptsWellFormedMap(t *testing.T) {
	t.Parallel()
	report, err := piimap.Validate([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Validate well-formed yaml errored: %v", err)
	}
	if !report.Valid {
		t.Errorf("expected Valid=true; got %+v", report)
	}
	if report.FieldCount != 3 {
		t.Errorf("FieldCount = %d; want 3", report.FieldCount)
	}
}

func TestValidate_RejectsMalformedYAML(t *testing.T) {
	t.Parallel()
	report, _ := piimap.Validate([]byte(malformedYAML))
	if report.Valid {
		t.Errorf("malformed YAML should fail validation")
	}
	if len(report.Errors) == 0 {
		t.Errorf("expected validation errors")
	}
}

func TestValidate_RejectsMissingDomain(t *testing.T) {
	t.Parallel()
	report, _ := piimap.Validate([]byte(missingFieldsYAML))
	if report.Valid {
		t.Errorf("missing domain should fail")
	}
}

func TestValidate_RejectsUnknownAction(t *testing.T) {
	t.Parallel()
	bad := `
domain: x
schema_version: 1
fields:
  - name: f
    pii_class: pii_direct
    action: incinerate
`
	report, _ := piimap.Validate([]byte(bad))
	if report.Valid {
		t.Errorf("unknown action 'incinerate' should fail")
	}
}

func TestValidate_RejectsUnknownPIIClass(t *testing.T) {
	t.Parallel()
	bad := `
domain: x
schema_version: 1
fields:
  - name: f
    pii_class: pii_super_secret
    action: tokenize
`
	report, _ := piimap.Validate([]byte(bad))
	if report.Valid {
		t.Errorf("unknown pii_class should fail")
	}
}

func TestValidate_AcceptsAllKnownActions(t *testing.T) {
	t.Parallel()
	for _, a := range piimap.AllActions() {
		yaml := "domain: x\nschema_version: 1\nfields:\n  - name: f\n    pii_class: pii_direct\n    action: " + string(a) + "\n"
		report, err := piimap.Validate([]byte(yaml))
		if err != nil {
			t.Errorf("action %s produced unexpected error: %v", a, err)
			continue
		}
		if !report.Valid {
			t.Errorf("action %s should validate; got errors %v", a, report.Errors)
		}
	}
}

// -----------------------------------------------------------------------------
// Parse
// -----------------------------------------------------------------------------

func TestParse_PopulatesAllFields(t *testing.T) {
	t.Parallel()
	m, err := piimap.Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Domain != "creation" {
		t.Errorf("Domain = %q; want creation", m.Domain)
	}
	if m.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d; want 1", m.SchemaVersion)
	}
	if len(m.Fields) != 3 {
		t.Errorf("len(Fields) = %d; want 3", len(m.Fields))
	}
	if m.Fields[0].Action != piimap.ActionTokenize {
		t.Errorf("Fields[0].Action = %q; want tokenize", m.Fields[0].Action)
	}
	if m.OnCreatorClosure != "anonymize_attribution" {
		t.Errorf("OnCreatorClosure = %q; want anonymize_attribution", m.OnCreatorClosure)
	}
}

// -----------------------------------------------------------------------------
// Repository / registry
// -----------------------------------------------------------------------------

func TestRegister_StoresMap(t *testing.T) {
	t.Parallel()
	r := piimap.NewInMemoryRepository()
	rec, err := r.Register(context.Background(), piimap.RegisterParams{
		Domain:   "creation",
		TenantID: tenantA,
		Gcid:     gcidA,
		YAML:     []byte(minimalYAML),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if rec.MapID == "" {
		t.Errorf("MapID empty")
	}
	if rec.Domain != "creation" {
		t.Errorf("Domain = %q; want creation", rec.Domain)
	}
	if rec.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d; want 1", rec.SchemaVersion)
	}
	if len(rec.Fields) != 3 {
		t.Errorf("Fields count = %d; want 3", len(rec.Fields))
	}
	if rec.Sha256 == "" {
		t.Errorf("Sha256 should be populated")
	}
}

func TestRegister_RejectsInvalidYAML(t *testing.T) {
	t.Parallel()
	r := piimap.NewInMemoryRepository()
	_, err := r.Register(context.Background(), piimap.RegisterParams{
		Domain: "creation", YAML: []byte(malformedYAML),
		TenantID: tenantA, Gcid: gcidA,
	})
	if err == nil {
		t.Errorf("Register should reject malformed YAML")
	}
}

func TestGet_ReturnsLatestVersion(t *testing.T) {
	t.Parallel()
	r := piimap.NewInMemoryRepository()
	ctx := context.Background()

	yaml1 := minimalYAML
	yaml2 := `
domain: creation
schema_version: 2
fields:
  - name: author_email
    pii_class: pii_direct
    action: tokenize
on_creator_closure: anonymize_attribution
`
	_, _ = r.Register(ctx, piimap.RegisterParams{Domain: "creation", TenantID: tenantA, Gcid: gcidA, YAML: []byte(yaml1)})
	_, _ = r.Register(ctx, piimap.RegisterParams{Domain: "creation", TenantID: tenantA, Gcid: gcidA, YAML: []byte(yaml2)})

	rec, err := r.Get(ctx, "creation")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d; want 2 (latest)", rec.SchemaVersion)
	}
}

func TestGet_NotFound(t *testing.T) {
	t.Parallel()
	r := piimap.NewInMemoryRepository()
	_, err := r.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Errorf("Get unknown domain should error")
	}
}

func TestList_ReturnsAllDomains(t *testing.T) {
	t.Parallel()
	r := piimap.NewInMemoryRepository()
	ctx := context.Background()
	for _, d := range []string{"creation", "delivery", "consumption"} {
		yaml := "domain: " + d + "\nschema_version: 1\nfields: []\non_creator_closure: anonymize_attribution\n"
		_, err := r.Register(ctx, piimap.RegisterParams{Domain: d, TenantID: tenantA, Gcid: gcidA, YAML: []byte(yaml)})
		if err != nil {
			t.Fatalf("Register %s: %v", d, err)
		}
	}
	items, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 3 {
		t.Errorf("len(List) = %d; want 3", len(items))
	}
}

// -----------------------------------------------------------------------------
// Completeness check — must cover every pii_class-tagged field
// -----------------------------------------------------------------------------

func TestValidate_RejectsFieldWithoutAction(t *testing.T) {
	t.Parallel()
	bad := `
domain: x
schema_version: 1
fields:
  - name: orphan_field
    pii_class: pii_direct
    action: ""
`
	report, _ := piimap.Validate([]byte(bad))
	if report.Valid {
		t.Errorf("field tagged pii_class without action must fail completeness")
	}
}

func TestValidate_RejectsFieldWithoutName(t *testing.T) {
	t.Parallel()
	bad := `
domain: x
schema_version: 1
fields:
  - name: ""
    pii_class: pii_direct
    action: tokenize
`
	report, _ := piimap.Validate([]byte(bad))
	if report.Valid {
		t.Errorf("field without name must fail")
	}
}
