// Package audit is the AuditEvent aggregate of the Governance domain.
//
// AuditEvent is APPEND-ONLY per the spec — never UPDATE existing. The
// repository's Append method enforces this by rejecting duplicate event_ids.
// Each appended event is part of a tamper-evident hash chain (PrevHash +
// EntryHash); see hash_chain.go.
//
// Per .claude/rules/ddd-enforcement.md: every Gatekeeper decision (allow OR
// deny) MUST be audited.
package audit

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
// Decision
// -----------------------------------------------------------------------------

// Decision is the verdict recorded on an AuditEvent.
type Decision string

const (
	DecisionPermitted Decision = "permitted"
	DecisionDenied    Decision = "denied"
)

// Valid reports whether d is permitted/denied.
func (d Decision) Valid() bool {
	switch d {
	case DecisionPermitted, DecisionDenied:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// AuditEvent aggregate
// -----------------------------------------------------------------------------

// Event is the AuditEvent aggregate. Once created and appended, it MUST NOT
// be mutated. There is no Update method on this type.
//
// Each appended Event is part of a tamper-evident hash chain (PrevHash +
// EntryHash). The repository populates these on Append.
type Event struct {
	EventID  string   `json:"event_id"`
	TenantID string   `json:"tenant_id"`
	Gcid     string   `json:"gcid"`
	Agid     string   `json:"agid,omitempty"` // nullable
	Action   string   `json:"action"`
	Resource string   `json:"resource"`
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason,omitempty"`

	// SubjectType + SubjectID identify the audited subject (atom, tenant,
	// user, agent, etc.). Optional for back-compat.
	SubjectType string `json:"subject_type,omitempty"`
	SubjectID   string `json:"subject_id,omitempty"`

	// ActorGcid is the GCID/AGID of the actor performing the action.
	// Falls back to Gcid for back-compat.
	ActorGcid string `json:"actor_gcid,omitempty"`

	// Before / After are JSON-serialised state snapshots (optional).
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`

	Traceparent string    `json:"traceparent,omitempty"`
	Tracestate  string    `json:"tracestate,omitempty"`
	CreatedAt   time.Time `json:"created_at"`

	// PrevHash is the EntryHash of the previously-appended entry on the
	// per-tenant chain. Empty for the genesis entry.
	PrevHash string `json:"prev_hash"`
	// EntryHash is SHA-256(canonical(entry) || prev_hash). Repository
	// populates this on Append.
	EntryHash string `json:"entry_hash"`
}

// NewParams is the constructor input.
type NewParams struct {
	TenantID    string
	Gcid        string
	Agid        string // nullable — pass "" if absent
	Action      string
	Resource    string
	Decision    Decision
	Reason      string
	SubjectType string
	SubjectID   string
	ActorGcid   string
	Before      string
	After       string
	Traceparent string
	Tracestate  string
}

// New constructs an AuditEvent. Validates required fields.
func New(p NewParams) (*Event, error) {
	if strings.TrimSpace(p.TenantID) == "" {
		return nil, errors.New("tenant_id is required")
	}
	if strings.TrimSpace(p.Gcid) == "" {
		return nil, errors.New("gcid is required")
	}
	if strings.TrimSpace(p.Action) == "" {
		return nil, errors.New("action is required")
	}
	if !p.Decision.Valid() {
		return nil, fmt.Errorf("invalid decision: %q", string(p.Decision))
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}

	actor := strings.TrimSpace(p.ActorGcid)
	if actor == "" {
		actor = p.Gcid
	}

	return &Event{
		EventID:     id.String(),
		TenantID:    p.TenantID,
		Gcid:        p.Gcid,
		Agid:        strings.TrimSpace(p.Agid),
		Action:      strings.TrimSpace(p.Action),
		Resource:    strings.TrimSpace(p.Resource),
		Decision:    p.Decision,
		Reason:      strings.TrimSpace(p.Reason),
		SubjectType: strings.TrimSpace(p.SubjectType),
		SubjectID:   strings.TrimSpace(p.SubjectID),
		ActorGcid:   actor,
		Before:      p.Before,
		After:       p.After,
		Traceparent: strings.TrimSpace(p.Traceparent),
		Tracestate:  strings.TrimSpace(p.Tracestate),
		// Truncate to microseconds: Postgres TIMESTAMPTZ stores microsecond
		// precision, so a nanosecond-precision CreatedAt would make the
		// EntryHash (computed here) mismatch the recompute at read time.
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}, nil
}

// -----------------------------------------------------------------------------
// Repository port
// -----------------------------------------------------------------------------

// ErrAlreadyExists is returned when Append is called with an event_id that
// already exists (an attempted UPDATE in disguise).
var ErrAlreadyExists = errors.New("audit event with that event_id already exists")

// ErrNotFound is returned by lookups when the entry is unknown.
var ErrNotFound = errors.New("audit entry not found")

// VerifyResult summarises a chain-verification pass over a tenant's entries.
type VerifyResult struct {
	Valid              bool   `json:"valid"`
	Verified           int    `json:"verified"`
	FirstBrokenEventID string `json:"first_broken_event_id,omitempty"`
	BrokenAtIndex      int    `json:"broken_at_index,omitempty"`
}

// Repository is the AuditEvent persistence port. Append-only:
// no Update / Delete methods exist by design.
type Repository interface {
	Append(ctx context.Context, e *Event) error
	Query(ctx context.Context, filter QueryFilter) ([]*Event, error)
	GetByID(ctx context.Context, eventID string) (*Event, error)
	VerifyEntry(ctx context.Context, eventID string) (bool, error)
	VerifyChain(ctx context.Context, tenantID string) (VerifyResult, error)
}

// QueryFilter is the read-side filter for Query.
type QueryFilter struct {
	TenantID    string
	SubjectID   string
	SubjectType string
	// Action scopes the query to a single audit_log.action discriminator
	// (e.g. "external_egress" for the O+ egress-audit read, CHO-2245). Empty
	// means "any action".
	Action string
	From   *time.Time
	To     *time.Time
	Limit  int
	Offset int
	Cursor string // opaque — for in-mem we treat as last-seen event_id
}

// -----------------------------------------------------------------------------
// In-memory implementation (dev/test only)
// -----------------------------------------------------------------------------

// InMemoryRepository is the dev/test implementation of Repository.
type InMemoryRepository struct {
	mu       sync.RWMutex
	events   map[string]*Event // keyed by EventID
	order    []string          // global insertion order
	tenantTo map[string]string // tenant -> last EntryHash on chain
}

// NewInMemoryRepository constructs an empty in-memory repo.
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		events:   make(map[string]*Event),
		tenantTo: make(map[string]string),
	}
}

// Append persists e. Rejects duplicate event_ids (append-only invariant).
// Computes PrevHash + EntryHash for the per-tenant chain.
func (m *InMemoryRepository) Append(_ context.Context, e *Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.events[e.EventID]; exists {
		return ErrAlreadyExists
	}
	prev := m.tenantTo[e.TenantID]
	e.PrevHash = prev
	e.EntryHash = ComputeHash(e, prev)

	clone := *e
	m.events[e.EventID] = &clone
	m.order = append(m.order, e.EventID)
	m.tenantTo[e.TenantID] = clone.EntryHash
	return nil
}

// Query returns events matching filter, in insertion order.
func (m *InMemoryRepository) Query(_ context.Context, f QueryFilter) ([]*Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*Event, 0, len(m.order))
	for _, id := range m.order {
		e := m.events[id]
		if f.TenantID != "" && e.TenantID != f.TenantID {
			continue
		}
		if f.SubjectID != "" && e.SubjectID != f.SubjectID {
			continue
		}
		if f.SubjectType != "" && e.SubjectType != f.SubjectType {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		if f.From != nil && e.CreatedAt.Before(*f.From) {
			continue
		}
		if f.To != nil && e.CreatedAt.After(*f.To) {
			continue
		}
		clone := *e
		out = append(out, &clone)
	}
	if f.Cursor != "" {
		// Skip past entries whose EventID <= cursor (UUIDv7 sortable).
		filtered := out[:0]
		past := false
		for _, ev := range out {
			if !past {
				if ev.EventID == f.Cursor {
					past = true
				}
				continue
			}
			filtered = append(filtered, ev)
		}
		out = filtered
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

// GetByID returns an event by its EventID, or ErrNotFound.
func (m *InMemoryRepository) GetByID(_ context.Context, eventID string) (*Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.events[eventID]
	if !ok {
		return nil, ErrNotFound
	}
	clone := *e
	return &clone, nil
}

// VerifyEntry recomputes the entry's hash and compares to the stored value.
// Returns false if tampering is detected.
func (m *InMemoryRepository) VerifyEntry(_ context.Context, eventID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.events[eventID]
	if !ok {
		return false, ErrNotFound
	}
	want := ComputeHash(e, e.PrevHash)
	return want == e.EntryHash, nil
}

// VerifyChain walks the per-tenant chain in insertion order, recomputing
// each EntryHash from the prior EntryHash + the entry's canonical fields,
// and checks the stored EntryHash matches. Reports the first broken entry.
func (m *InMemoryRepository) VerifyChain(_ context.Context, tenantID string) (VerifyResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prev := ""
	verified := 0
	for _, id := range m.order {
		e := m.events[id]
		if e.TenantID != tenantID {
			continue
		}
		want := ComputeHash(e, prev)
		if want != e.EntryHash || e.PrevHash != prev {
			return VerifyResult{
				Valid:              false,
				Verified:           verified,
				FirstBrokenEventID: e.EventID,
				BrokenAtIndex:      verified,
			}, nil
		}
		verified++
		prev = e.EntryHash
	}
	return VerifyResult{Valid: true, Verified: verified}, nil
}

// TamperEntryHash is a TEST-ONLY seam to simulate post-write tampering.
// Production deployments must NOT rely on this method. It exists in the
// in-memory repo so tests can prove VerifyChain detects modification.
func (m *InMemoryRepository) TamperEntryHash(eventID, newHash string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.events[eventID]; ok {
		e.EntryHash = newHash
	}
}
