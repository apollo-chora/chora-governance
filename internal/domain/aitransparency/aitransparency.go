// Package aitransparency is the AI Transparency Notice aggregate of the
// Governance domain (ADR-225). It implements the EU AI Act Art 50 / IMDA
// MGF-GenAI transparency FLOOR as a NOTICE (acknowledgement), never a consent
// gate — AI availability is never blocked.
//
// Server-side responsibilities modelled here (ADR-225 §3):
//
//   - RECORD: an append-only transparency-evidence acknowledgement
//     (notice-shown + acknowledged + disclosure VERSION), GCID-scoped, feeding
//     O+ D2 (ISO 25059 "User Controllability — consent UI presence").
//   - SERVE: the versioned disclosure copy as config-as-data (DisclosureVersion),
//     never inline in the FE bundle.
//   - Age-appropriate wording via the AgeSignalResolver port (ADR-225 §D6.2 —
//     HYBRID age signal). The StandardAgeSignalResolver is the REAL default:
//     no age signal wired yet -> unknown -> the standard (safe) wording. That
//     is a correct answer for today's reality, NOT a stub.
//
// This aggregate does NOT store consent — it is a distinct legal instrument
// from ADR-117 GDPR Art 7 consent (chora_identity). See ADR-225 §2.
package aitransparency

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Sentinel errors.
var (
	// ErrNotFound is returned when no acknowledgement exists for a GCID.
	ErrNotFound = errors.New("aitransparency: not found")
	// ErrNoActiveDisclosure is returned when no active disclosure version exists.
	ErrNoActiveDisclosure = errors.New("aitransparency: no active disclosure version")
)

// DefaultLocale is the fail-safe locale — the seed migration always carries
// (en, standard), so locale/variant fallback always terminates here.
const DefaultLocale = "en"

// =============================================================================
// Age signal — HYBRID (ADR-225 §D6.2)
// =============================================================================

// AgeBand is the resolved age classification for a learner.
type AgeBand string

const (
	// AgeBandAdult — learner is known to be an adult.
	AgeBandAdult AgeBand = "adult"
	// AgeBandMinor — learner is known to be a minor -> age-appropriate wording.
	AgeBandMinor AgeBand = "minor"
	// AgeBandUnknown — no reliable age signal -> the standard (safe) wording.
	AgeBandUnknown AgeBand = "unknown"
)

// AgeSignalSource records WHERE a resolved band came from (audit + O+).
type AgeSignalSource string

const (
	// AgeSourceTenantBand — a tenant-declared cohort age band (source 1).
	AgeSourceTenantBand AgeSignalSource = "tenant_band"
	// AgeSourceSelfAttestation — registration-time self-attestation (source 2).
	AgeSourceSelfAttestation AgeSignalSource = "self_attestation"
	// AgeSourceNone — no signal available (the current reality).
	AgeSourceNone AgeSignalSource = "none"
)

// AgeSignal is the resolved age classification + its provenance.
type AgeSignal struct {
	Band   AgeBand
	Source AgeSignalSource
}

// AgeSignalResolver is the port that resolves a learner's age band. The HYBRID
// design (ADR-225 §D6.2) resolves in precedence order: tenant-band ->
// self-attestation -> unknown. Concrete source adapters are roadmapped
// follow-up slices; the port + the standard default ship in the backbone.
type AgeSignalResolver interface {
	Resolve(ctx context.Context, gcid, tenantID string) (AgeSignal, error)
}

// StandardAgeSignalResolver is the REAL default resolver: with no age-signal
// source wired yet, every learner resolves to {unknown, none} -> the standard
// (safe, universally-accessible) wording. This is a correct, honest answer for
// today's deployed reality — NOT a stub or placeholder success.
type StandardAgeSignalResolver struct{}

// Resolve always returns {unknown, none}.
func (StandardAgeSignalResolver) Resolve(context.Context, string, string) (AgeSignal, error) {
	return AgeSignal{Band: AgeBandUnknown, Source: AgeSourceNone}, nil
}

var _ AgeSignalResolver = StandardAgeSignalResolver{}

// Variant is the disclosure-copy variant.
type Variant string

const (
	// VariantStandard — the standard, plain-language wording (the safe default).
	VariantStandard Variant = "standard"
	// VariantMinor — even simpler, age-appropriate wording for known minors.
	VariantMinor Variant = "minor"
)

// VariantForBand maps a resolved age band to the copy variant. Only a KNOWN
// minor gets the minor variant; adult + unknown both fail safe to standard.
func VariantForBand(b AgeBand) Variant {
	if b == AgeBandMinor {
		return VariantMinor
	}
	return VariantStandard
}

// =============================================================================
// Disclosure copy — config-as-data value objects
// =============================================================================

// NoticeCopy is the first-interaction notice (one acknowledgement action).
type NoticeCopy struct {
	Title  string `json:"title"`
	Body   string `json:"body"`
	Action string `json:"action"`
}

// BadgeCopy is the persistent AI badge (chat header + profile).
type BadgeCopy struct {
	Label   string `json:"label"`
	Tooltip string `json:"tooltip"`
}

// LabelCopy is a single inline label (label + tooltip).
type LabelCopy struct {
	Label   string `json:"label"`
	Tooltip string `json:"tooltip"`
}

// InlineLabels is the set of per-artifact inline labels.
type InlineLabels struct {
	AiGenerated LabelCopy `json:"aiGenerated"`
	AiAssisted  LabelCopy `json:"aiAssisted"`
	DoseHeader  LabelCopy `json:"doseHeader"`
}

// DisclosureCopy is the full copy block served for a (locale, variant).
type DisclosureCopy struct {
	Notice       NoticeCopy   `json:"notice"`
	Badge        BadgeCopy    `json:"badge"`
	InlineLabels InlineLabels `json:"inlineLabels"`
}

// =============================================================================
// DisclosureVersion aggregate (config-as-data, governance-owned)
// =============================================================================

// DisclosureStatus is the lifecycle state of a disclosure version.
type DisclosureStatus string

const (
	StatusDraft    DisclosureStatus = "draft"
	StatusActive   DisclosureStatus = "active"
	StatusArchived DisclosureStatus = "archived"
)

// DisclosureVersion is the versioned disclosure config (ADR-225 §D5.1). One row
// is active platform-wide at a time; per-GCID acknowledgement compares against
// it. Locales maps locale -> variant -> copy.
type DisclosureVersion struct {
	Version                   string
	Status                    DisclosureStatus
	RequiresReacknowledgement bool
	EffectiveFrom             time.Time
	Scope                     string
	Locales                   map[string]map[Variant]DisclosureCopy
	CreatedBy                 string
	ApprovedBy                string
}

// ResolveCopy returns the copy for (locale, variant) with a deterministic
// fallback ladder: (locale,variant) -> (locale,standard) -> (default,variant)
// -> (default,standard). Returns the copy + the locale + variant actually
// resolved. The seed always carries (en,standard) so this terminates.
func (v *DisclosureVersion) ResolveCopy(locale string, variant Variant, defaultLocale string) (DisclosureCopy, string, Variant) {
	if defaultLocale == "" {
		defaultLocale = DefaultLocale
	}
	tryLocales := dedupe(locale, defaultLocale)
	tryVariants := dedupeVariants(variant, VariantStandard)
	for _, loc := range tryLocales {
		byVariant, ok := v.Locales[loc]
		if !ok {
			continue
		}
		for _, va := range tryVariants {
			if c, ok := byVariant[va]; ok {
				return c, loc, va
			}
		}
	}
	return DisclosureCopy{}, "", ""
}

func dedupe(a, b string) []string {
	if a == "" {
		a = b
	}
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}

func dedupeVariants(a, b Variant) []Variant {
	if a == "" {
		a = b
	}
	if a == b {
		return []Variant{a}
	}
	return []Variant{a, b}
}

// =============================================================================
// Acknowledgement aggregate (append-only transparency evidence)
// =============================================================================

// Surface is the CHORA surface where the notice was shown.
type Surface string

// Scope is the AI capability the acknowledgement covers.
type Scope string

// Acknowledgement is one append-only transparency-evidence record: a learner
// (GCID) acknowledged a specific disclosure version. Feeds O+ D2.
type Acknowledgement struct {
	ID                string    `json:"id"`
	GCID              string    `json:"gcid"`
	TenantID          string    `json:"tenantId"`
	DisclosureVersion string    `json:"disclosureVersion"`
	Surface           Surface   `json:"surface"`
	Scope             Scope     `json:"scope"`
	FirstShownAt      time.Time `json:"firstShownAt"`
	AcknowledgedAt    time.Time `json:"acknowledgedAt"`
	Locale            string    `json:"locale"`
	MinorMode         bool      `json:"minorMode"`
	CreatedAt         time.Time `json:"createdAt"`
}

// AcknowledgeParams is the acknowledgement constructor input.
type AcknowledgeParams struct {
	ID           string
	GCID         string
	TenantID     string
	Version      string
	Surface      Surface
	Scope        Scope
	FirstShownAt time.Time
	Locale       string
	MinorMode    bool
}

// NewAcknowledgement constructs + validates an acknowledgement. Timestamps
// default to now (UTC); FirstShownAt defaults to AcknowledgedAt when zero.
func NewAcknowledgement(p AcknowledgeParams) (*Acknowledgement, error) {
	for k, val := range map[string]string{
		"gcid":               p.GCID,
		"tenant_id":          p.TenantID,
		"disclosure_version": p.Version,
		"surface":            string(p.Surface),
		"scope":              string(p.Scope),
	} {
		if strings.TrimSpace(val) == "" {
			return nil, fmt.Errorf("aitransparency: %s is required", k)
		}
	}
	now := time.Now().UTC()
	shown := p.FirstShownAt
	if shown.IsZero() {
		shown = now
	}
	locale := strings.TrimSpace(p.Locale)
	if locale == "" {
		locale = DefaultLocale
	}
	return &Acknowledgement{
		ID:                strings.TrimSpace(p.ID),
		GCID:              p.GCID,
		TenantID:          p.TenantID,
		DisclosureVersion: p.Version,
		Surface:           p.Surface,
		Scope:             p.Scope,
		FirstShownAt:      shown.UTC(),
		AcknowledgedAt:    now,
		Locale:            locale,
		MinorMode:         p.MinorMode,
		CreatedAt:         now,
	}, nil
}

// =============================================================================
// Repository port
// =============================================================================

// Repository is the transparency-evidence + disclosure-config persistence port.
type Repository interface {
	// ActiveDisclosureVersion returns the current active platform disclosure
	// version, or ErrNoActiveDisclosure.
	ActiveDisclosureVersion(ctx context.Context) (*DisclosureVersion, error)
	// LatestAcknowledgement returns the most recent acknowledgement for gcid,
	// or ErrNotFound. tenantID scopes the RLS-partitioned pg read (the
	// in-memory impl is tenant-agnostic / per-GCID).
	LatestAcknowledgement(ctx context.Context, gcid, tenantID string) (*Acknowledgement, error)
	// AppendAcknowledgement persists an acknowledgement. Idempotent on
	// (gcid, disclosure_version) — a duplicate is a no-op success.
	AppendAcknowledgement(ctx context.Context, a *Acknowledgement) error
}

// =============================================================================
// Service — resolution (must_acknowledge + copy) + acknowledge
// =============================================================================

// State is the resolved transparency state for a learner — the GET DTO source.
type State struct {
	MustAcknowledge     bool
	CurrentVersion      string
	AcknowledgedVersion *string
	Disclosure          Disclosure
	AgeSignalSource     AgeSignalSource
}

// Disclosure is the served copy block (version + resolved locale/variant + copy).
type Disclosure struct {
	Version         string
	Locale          string
	AudienceVariant Variant
	Copy            DisclosureCopy
}

// Service composes the repository + age-signal resolver into the read
// (GetState) + write (Acknowledge) use cases.
type Service struct {
	repo          Repository
	age           AgeSignalResolver
	defaultLocale string
	now           func() time.Time
}

// NewService constructs the service. A nil ageResolver defaults to the
// StandardAgeSignalResolver (the real unknown->standard default).
func NewService(repo Repository, ageResolver AgeSignalResolver) *Service {
	if ageResolver == nil {
		ageResolver = StandardAgeSignalResolver{}
	}
	return &Service{
		repo:          repo,
		age:           ageResolver,
		defaultLocale: DefaultLocale,
		now:           func() time.Time { return time.Now().UTC() },
	}
}

// GetState resolves must_acknowledge + the age-appropriate, localised copy for
// a learner. The age-resolver failing is fail-safe: it degrades to the standard
// (safe) variant rather than erroring the whole read.
func (s *Service) GetState(ctx context.Context, gcid, tenantID, locale string) (State, error) {
	active, err := s.repo.ActiveDisclosureVersion(ctx)
	if err != nil {
		return State{}, err
	}
	latest, err := s.repo.LatestAcknowledgement(ctx, gcid, tenantID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return State{}, err
	}

	band, source := s.resolveBand(ctx, gcid, tenantID)
	variant := VariantForBand(band)
	copyBlock, resolvedLocale, resolvedVariant := active.ResolveCopy(locale, variant, s.defaultLocale)

	var ackVer *string
	mustAck := true
	if latest != nil {
		v := latest.DisclosureVersion
		ackVer = &v
		// Acked current version -> no prompt. Acked an older version -> re-prompt
		// only when the active version is a MATERIAL change (RequiresReack).
		// Editorial bumps serve the new copy without forcing re-acknowledgement.
		if latest.DisclosureVersion == active.Version {
			mustAck = false
		} else {
			mustAck = active.RequiresReacknowledgement
		}
	}

	return State{
		MustAcknowledge:     mustAck,
		CurrentVersion:      active.Version,
		AcknowledgedVersion: ackVer,
		AgeSignalSource:     source,
		Disclosure: Disclosure{
			Version:         active.Version,
			Locale:          resolvedLocale,
			AudienceVariant: resolvedVariant,
			Copy:            copyBlock,
		},
	}, nil
}

// resolveBand resolves the age band, failing safe to {unknown,none} on error.
func (s *Service) resolveBand(ctx context.Context, gcid, tenantID string) (AgeBand, AgeSignalSource) {
	sig, err := s.age.Resolve(ctx, gcid, tenantID)
	if err != nil {
		// Fail-safe: never block the transparency read on an age lookup; fall
		// back to the standard (safe) wording.
		return AgeBandUnknown, AgeSourceNone
	}
	if sig.Band == "" {
		return AgeBandUnknown, AgeSourceNone
	}
	return sig.Band, sig.Source
}

// Acknowledge records a learner's acknowledgement. A blank Version resolves to
// the active disclosure version. MinorMode is stamped from the resolved age
// band. Idempotent on (gcid, version) at the repository layer.
func (s *Service) Acknowledge(ctx context.Context, p AcknowledgeParams) (*Acknowledgement, error) {
	if strings.TrimSpace(p.Version) == "" {
		active, err := s.repo.ActiveDisclosureVersion(ctx)
		if err != nil {
			return nil, err
		}
		p.Version = active.Version
	}
	band, _ := s.resolveBand(ctx, p.GCID, p.TenantID)
	if band == AgeBandMinor {
		p.MinorMode = true
	}
	ack, err := NewAcknowledgement(p)
	if err != nil {
		return nil, err
	}
	if err := s.repo.AppendAcknowledgement(ctx, ack); err != nil {
		return nil, err
	}
	return ack, nil
}

// =============================================================================
// InMemoryRepository — dev/test implementation
// =============================================================================

// InMemoryRepository is the in-memory Repository. Idempotent on
// (gcid, disclosure_version).
type InMemoryRepository struct {
	mu     sync.RWMutex
	active *DisclosureVersion
	acks   map[string][]*Acknowledgement // gcid -> acks in append order
}

// NewInMemoryRepository constructs the repository seeded with the active
// disclosure version (may be nil -> ActiveDisclosureVersion returns
// ErrNoActiveDisclosure).
func NewInMemoryRepository(active *DisclosureVersion) *InMemoryRepository {
	return &InMemoryRepository{
		active: active,
		acks:   make(map[string][]*Acknowledgement),
	}
}

// ActiveDisclosureVersion returns the seeded active version.
func (m *InMemoryRepository) ActiveDisclosureVersion(context.Context) (*DisclosureVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return nil, ErrNoActiveDisclosure
	}
	return m.active, nil
}

// LatestAcknowledgement returns the most-recently-acknowledged row for gcid.
// tenantID is ignored — the in-memory impl is tenant-agnostic (per-GCID).
func (m *InMemoryRepository) LatestAcknowledgement(_ context.Context, gcid, _ string) (*Acknowledgement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := m.acks[gcid]
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	latest := list[0]
	for _, a := range list[1:] {
		if a.AcknowledgedAt.After(latest.AcknowledgedAt) {
			latest = a
		}
	}
	return latest, nil
}

// AppendAcknowledgement appends, idempotent on (gcid, disclosure_version).
func (m *InMemoryRepository) AppendAcknowledgement(_ context.Context, a *Acknowledgement) error {
	if a == nil {
		return errors.New("aitransparency: nil acknowledgement")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.acks[a.GCID] {
		if existing.DisclosureVersion == a.DisclosureVersion {
			return nil // idempotent
		}
	}
	m.acks[a.GCID] = append(m.acks[a.GCID], a)
	return nil
}

var _ Repository = (*InMemoryRepository)(nil)
