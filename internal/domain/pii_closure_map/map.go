// Package pii_closure_map is the PIIClosureMap aggregate of the Governance
// domain.
//
// Per .claude/rules/ddd-enforcement.md (Account Closure section): each domain
// owns a PII_Closure_Map.yaml declaring fields-to-tokenize, retention rules,
// and on-creator-closure behaviour. The Governance service centrally registers
// these maps so the federated saga + Closure Orchestrator have a single
// inspection surface (per Tier 3 D11 + account-closure-saga skill).
//
// Schema (YAML):
//
//	domain: <core domain name — e.g., creation, consumption>
//	schema_version: <int>
//	fields:
//	  - name: <db column / json field>
//	    pii_class: <pii_direct | pii_indirect | non_pii>
//	    action: <tokenize | crypto_shred | retain | redact>
//	on_creator_closure: <anonymize_attribution | retain_full | drop>
package pii_closure_map

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// -----------------------------------------------------------------------------
// Action / PIIClass enums
// -----------------------------------------------------------------------------

// Action is what the Closure Orchestrator does to the field on closure.
type Action string

const (
	ActionTokenize    Action = "tokenize"
	ActionCryptoShred Action = "crypto_shred"
	ActionRetain      Action = "retain"
	ActionRedact      Action = "redact"
)

// AllActions returns the supported actions.
func AllActions() []Action {
	return []Action{ActionTokenize, ActionCryptoShred, ActionRetain, ActionRedact}
}

// Valid reports whether a is a recognised closure action.
func (a Action) Valid() bool {
	for _, x := range AllActions() {
		if x == a {
			return true
		}
	}
	return false
}

// PIIClass is the PII classification for a field.
type PIIClass string

const (
	PIIDirect   PIIClass = "pii_direct"
	PIIIndirect PIIClass = "pii_indirect"
	PIINone     PIIClass = "non_pii"
)

// Valid reports whether p is a recognised PII class.
func (p PIIClass) Valid() bool {
	switch p {
	case PIIDirect, PIIIndirect, PIINone:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// Schema types
// -----------------------------------------------------------------------------

// Field is one row in the PII closure map.
type Field struct {
	Name     string   `yaml:"name" json:"name"`
	PIIClass PIIClass `yaml:"pii_class" json:"pii_class"`
	Action   Action   `yaml:"action" json:"action"`
}

// Map is the parsed PII_Closure_Map.yaml.
type Map struct {
	Domain           string  `yaml:"domain" json:"domain"`
	SchemaVersion    int     `yaml:"schema_version" json:"schema_version"`
	Fields           []Field `yaml:"fields" json:"fields"`
	OnCreatorClosure string  `yaml:"on_creator_closure" json:"on_creator_closure"`
}

// -----------------------------------------------------------------------------
// Validate / Parse
// -----------------------------------------------------------------------------

// ValidationReport is the structured outcome of Validate.
type ValidationReport struct {
	Valid      bool     `json:"valid"`
	Domain     string   `json:"domain"`
	FieldCount int      `json:"field_count"`
	Errors     []string `json:"errors,omitempty"`
}

// Validate parses + checks a YAML map for syntax + completeness.
// Completeness: every field tagged with pii_class MUST declare an action.
// Allowed pii_class: pii_direct | pii_indirect | non_pii.
// Allowed action: see AllActions().
func Validate(yamlBytes []byte) (ValidationReport, error) {
	var report ValidationReport
	var m Map
	if err := yaml.Unmarshal(yamlBytes, &m); err != nil {
		report.Errors = append(report.Errors, "invalid yaml: "+err.Error())
		return report, nil
	}
	if strings.TrimSpace(m.Domain) == "" {
		report.Errors = append(report.Errors, "domain is required")
	}
	if m.SchemaVersion < 1 {
		report.Errors = append(report.Errors, "schema_version must be >= 1")
	}
	for i, f := range m.Fields {
		if strings.TrimSpace(f.Name) == "" {
			report.Errors = append(report.Errors, fmt.Sprintf("field[%d].name is required", i))
		}
		if !f.PIIClass.Valid() {
			report.Errors = append(report.Errors, fmt.Sprintf("field[%d].pii_class invalid: %q", i, f.PIIClass))
		}
		if !f.Action.Valid() {
			report.Errors = append(report.Errors, fmt.Sprintf("field[%d].action invalid: %q", i, f.Action))
		}
	}
	report.Domain = m.Domain
	report.FieldCount = len(m.Fields)
	report.Valid = len(report.Errors) == 0
	return report, nil
}

// Parse unmarshals YAML into a Map and validates. Returns the typed Map on
// success.
func Parse(yamlBytes []byte) (*Map, error) {
	var m Map
	if err := yaml.Unmarshal(yamlBytes, &m); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	report, _ := Validate(yamlBytes)
	if !report.Valid {
		return nil, fmt.Errorf("invalid map: %s", strings.Join(report.Errors, "; "))
	}
	return &m, nil
}

// -----------------------------------------------------------------------------
// Registered record + repository port
// -----------------------------------------------------------------------------

// Record is a registered PII closure map.
type Record struct {
	MapID            string    `json:"map_id"` // UUIDv7
	Domain           string    `json:"domain"`
	TenantID         string    `json:"tenant_id"` // owning tenant of the registration (e.g., "platform")
	SchemaVersion    int       `json:"schema_version"`
	Fields           []Field   `json:"fields"`
	OnCreatorClosure string    `json:"on_creator_closure"`
	Sha256           string    `json:"sha256"` // hex of the YAML bytes
	RegisteredAt     time.Time `json:"registered_at"`
	RegisteredByGcid string    `json:"registered_by_gcid"`
}

// RegisterParams is the input for Repository.Register.
type RegisterParams struct {
	Domain   string
	TenantID string
	Gcid     string
	YAML     []byte
}

// Repository is the persistence port for the PII closure map registry.
type Repository interface {
	Register(ctx context.Context, p RegisterParams) (*Record, error)
	Get(ctx context.Context, domain string) (*Record, error)
	List(ctx context.Context) ([]*Record, error)
}

// ErrNotFound is the canonical sentinel.
var ErrNotFound = errors.New("pii closure map not found")

// InMemoryRepository is the dev/test implementation.
type InMemoryRepository struct {
	mu      sync.RWMutex
	records map[string][]*Record // domain -> all registered versions (newest last)
}

// NewInMemoryRepository constructs an empty registry.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{records: make(map[string][]*Record)}
}

// Register validates + stores a YAML map for domain. Always appends a new
// version (does not overwrite).
func (r *InMemoryRepository) Register(_ context.Context, p RegisterParams) (*Record, error) {
	if strings.TrimSpace(p.Domain) == "" {
		return nil, errors.New("domain is required")
	}
	if strings.TrimSpace(p.TenantID) == "" {
		return nil, errors.New("tenant_id is required")
	}
	parsed, err := Parse(p.YAML)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(parsed.Domain, p.Domain) {
		return nil, fmt.Errorf("yaml domain %q does not match path domain %q", parsed.Domain, p.Domain)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}
	sum := sha256.Sum256(p.YAML)

	rec := &Record{
		MapID:            id.String(),
		Domain:           parsed.Domain,
		TenantID:         p.TenantID,
		SchemaVersion:    parsed.SchemaVersion,
		Fields:           append([]Field(nil), parsed.Fields...),
		OnCreatorClosure: parsed.OnCreatorClosure,
		Sha256:           hex.EncodeToString(sum[:]),
		RegisteredAt:     time.Now().UTC(),
		RegisteredByGcid: p.Gcid,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[parsed.Domain] = append(r.records[parsed.Domain], rec)
	clone := *rec
	return &clone, nil
}

// Get returns the latest version for a domain.
func (r *InMemoryRepository) Get(_ context.Context, domain string) (*Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	versions, ok := r.records[domain]
	if !ok || len(versions) == 0 {
		return nil, ErrNotFound
	}
	clone := *versions[len(versions)-1]
	return &clone, nil
}

// List returns the latest version for every registered domain.
func (r *InMemoryRepository) List(_ context.Context) ([]*Record, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Record, 0, len(r.records))
	for _, versions := range r.records {
		if len(versions) == 0 {
			continue
		}
		clone := *versions[len(versions)-1]
		out = append(out, &clone)
	}
	return out, nil
}
