package aitransparency_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/aitransparency"
)

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// seedVersion builds a config-as-data disclosure version with en{standard,minor}
// + zh{standard} copy — mirrors the migration 0011 seed shape.
func seedVersion(version string, requiresReack bool) *aitransparency.DisclosureVersion {
	return &aitransparency.DisclosureVersion{
		Version:                   version,
		Status:                    aitransparency.StatusActive,
		RequiresReacknowledgement: requiresReack,
		EffectiveFrom:             time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Scope:                     "platform",
		CreatedBy:                 "governance-architect",
		ApprovedBy:                "dale",
		Locales: map[string]map[aitransparency.Variant]aitransparency.DisclosureCopy{
			"en": {
				aitransparency.VariantStandard: {
					Notice: aitransparency.NoticeCopy{Title: "Say hi", Body: "AI powered", Action: "Got it"},
					Badge:  aitransparency.BadgeCopy{Label: "AI companion", Tooltip: "AI can be wrong"},
					InlineLabels: aitransparency.InlineLabels{
						AiGenerated: aitransparency.LabelCopy{Label: "AI-generated", Tooltip: "Made by AI"},
						AiAssisted:  aitransparency.LabelCopy{Label: "AI-assisted", Tooltip: "Reviewed by a person"},
						DoseHeader:  aitransparency.LabelCopy{Label: "Picked for you by AI", Tooltip: "Chosen by AI"},
					},
				},
				aitransparency.VariantMinor: {
					Notice: aitransparency.NoticeCopy{Title: "Meet your Familiar", Body: "friendly AI helper", Action: "Okay!"},
					Badge:  aitransparency.BadgeCopy{Label: "AI companion", Tooltip: "AI can be wrong"},
					InlineLabels: aitransparency.InlineLabels{
						AiGenerated: aitransparency.LabelCopy{Label: "Made by AI", Tooltip: "AI made this"},
					},
				},
			},
			"zh": {
				aitransparency.VariantStandard: {
					Notice: aitransparency.NoticeCopy{Title: "你好", Body: "AI", Action: "知道了"},
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// AgeSignalResolver — the REAL default (not a stub)
// -----------------------------------------------------------------------------

func TestStandardAgeSignalResolver_ReturnsUnknownNone(t *testing.T) {
	got, err := aitransparency.StandardAgeSignalResolver{}.Resolve(context.Background(), "gcid-1", "tenant-1")
	if err != nil {
		t.Fatalf("Resolve: unexpected err %v", err)
	}
	if got.Band != aitransparency.AgeBandUnknown {
		t.Errorf("Band = %q, want unknown (real fail-safe default)", got.Band)
	}
	if got.Source != aitransparency.AgeSourceNone {
		t.Errorf("Source = %q, want none", got.Source)
	}
}

func TestVariantForBand(t *testing.T) {
	cases := map[aitransparency.AgeBand]aitransparency.Variant{
		aitransparency.AgeBandMinor:   aitransparency.VariantMinor,
		aitransparency.AgeBandAdult:   aitransparency.VariantStandard,
		aitransparency.AgeBandUnknown: aitransparency.VariantStandard, // unknown -> safe standard
	}
	for band, want := range cases {
		if got := aitransparency.VariantForBand(band); got != want {
			t.Errorf("VariantForBand(%q) = %q, want %q", band, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// DisclosureVersion.ResolveCopy — locale + variant fallback
// -----------------------------------------------------------------------------

func TestResolveCopy_ExactMatch(t *testing.T) {
	v := seedVersion("2026-07-01", true)
	c, loc, variant := v.ResolveCopy("en", aitransparency.VariantMinor, "en")
	if loc != "en" || variant != aitransparency.VariantMinor {
		t.Fatalf("resolved (%q,%q), want (en,minor)", loc, variant)
	}
	if c.Notice.Title != "Meet your Familiar" {
		t.Errorf("minor notice title = %q", c.Notice.Title)
	}
}

func TestResolveCopy_VariantFallbackToStandard(t *testing.T) {
	v := seedVersion("2026-07-01", true)
	// zh has only standard — asking for minor must fall back to zh/standard.
	c, loc, variant := v.ResolveCopy("zh", aitransparency.VariantMinor, "en")
	if loc != "zh" || variant != aitransparency.VariantStandard {
		t.Fatalf("resolved (%q,%q), want (zh,standard)", loc, variant)
	}
	if c.Notice.Title != "你好" {
		t.Errorf("zh notice title = %q", c.Notice.Title)
	}
}

func TestResolveCopy_LocaleFallbackToDefault(t *testing.T) {
	v := seedVersion("2026-07-01", true)
	// unknown locale -> default en; variant minor exists in en.
	c, loc, variant := v.ResolveCopy("fr", aitransparency.VariantMinor, "en")
	if loc != "en" || variant != aitransparency.VariantMinor {
		t.Fatalf("resolved (%q,%q), want (en,minor)", loc, variant)
	}
	if c.Notice.Action != "Okay!" {
		t.Errorf("action = %q", c.Notice.Action)
	}
}

// -----------------------------------------------------------------------------
// Acknowledgement constructor
// -----------------------------------------------------------------------------

func TestNewAcknowledgement_Valid(t *testing.T) {
	a, err := aitransparency.NewAcknowledgement(aitransparency.AcknowledgeParams{
		ID:       "01J-ack",
		GCID:     "gcid-1",
		TenantID: "tenant-1",
		Version:  "2026-07-01",
		Surface:  "familiar",
		Scope:    "familiar_chat",
		Locale:   "en",
	})
	if err != nil {
		t.Fatalf("NewAcknowledgement: %v", err)
	}
	if a.AcknowledgedAt.IsZero() || a.CreatedAt.IsZero() || a.FirstShownAt.IsZero() {
		t.Errorf("timestamps must default to non-zero: %+v", a)
	}
	if a.MinorMode {
		t.Errorf("MinorMode should default false")
	}
}

func TestNewAcknowledgement_RejectsBlank(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    aitransparency.AcknowledgeParams
	}{
		{"no gcid", aitransparency.AcknowledgeParams{TenantID: "t", Version: "v", Surface: "familiar", Scope: "familiar_chat"}},
		{"no tenant", aitransparency.AcknowledgeParams{GCID: "g", Version: "v", Surface: "familiar", Scope: "familiar_chat"}},
		{"no version", aitransparency.AcknowledgeParams{GCID: "g", TenantID: "t", Surface: "familiar", Scope: "familiar_chat"}},
		{"no surface", aitransparency.AcknowledgeParams{GCID: "g", TenantID: "t", Version: "v", Scope: "familiar_chat"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aitransparency.NewAcknowledgement(tc.p); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// InMemoryRepository
// -----------------------------------------------------------------------------

func TestInMemoryRepository_AckIdempotentOnGcidVersion(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", true))
	ctx := context.Background()
	mk := func(id string) *aitransparency.Acknowledgement {
		a, _ := aitransparency.NewAcknowledgement(aitransparency.AcknowledgeParams{
			ID: id, GCID: "gcid-1", TenantID: "tenant-1", Version: "2026-07-01",
			Surface: "familiar", Scope: "familiar_chat", Locale: "en",
		})
		return a
	}
	if err := repo.AppendAcknowledgement(ctx, mk("a1")); err != nil {
		t.Fatalf("append1: %v", err)
	}
	// second append same (gcid, version) is idempotent — no error, no dup.
	if err := repo.AppendAcknowledgement(ctx, mk("a2")); err != nil {
		t.Fatalf("append2 (idempotent): %v", err)
	}
	latest, err := repo.LatestAcknowledgement(ctx, "gcid-1", "tenant-1")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.DisclosureVersion != "2026-07-01" {
		t.Errorf("latest version = %q", latest.DisclosureVersion)
	}
}

func TestInMemoryRepository_LatestNotFound(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", true))
	_, err := repo.LatestAcknowledgement(context.Background(), "nobody", "tenant-1")
	if !errors.Is(err, aitransparency.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestInMemoryRepository_NoActiveDisclosure(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(nil)
	_, err := repo.ActiveDisclosureVersion(context.Background())
	if !errors.Is(err, aitransparency.ErrNoActiveDisclosure) {
		t.Errorf("err = %v, want ErrNoActiveDisclosure", err)
	}
}

// -----------------------------------------------------------------------------
// Service.GetState — must_acknowledge + copy selection
// -----------------------------------------------------------------------------

func TestGetState_NeverAcknowledged_MustAck(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", true))
	svc := aitransparency.NewService(repo, nil) // nil -> StandardAgeSignalResolver
	st, err := svc.GetState(context.Background(), "gcid-1", "tenant-1", "en")
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if !st.MustAcknowledge {
		t.Errorf("MustAcknowledge = false, want true (never acked)")
	}
	if st.CurrentVersion != "2026-07-01" {
		t.Errorf("CurrentVersion = %q", st.CurrentVersion)
	}
	if st.AcknowledgedVersion != nil {
		t.Errorf("AcknowledgedVersion = %v, want nil", st.AcknowledgedVersion)
	}
	// unknown age -> standard variant, en copy.
	if st.Disclosure.AudienceVariant != aitransparency.VariantStandard {
		t.Errorf("variant = %q, want standard", st.Disclosure.AudienceVariant)
	}
	if st.Disclosure.Copy.Notice.Title != "Say hi" {
		t.Errorf("notice title = %q", st.Disclosure.Copy.Notice.Title)
	}
}

func TestGetState_AckedCurrent_NoMustAck(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", true))
	svc := aitransparency.NewService(repo, nil)
	ctx := context.Background()
	if _, err := svc.Acknowledge(ctx, aitransparency.AcknowledgeParams{
		ID: "a1", GCID: "gcid-1", TenantID: "tenant-1", Version: "2026-07-01",
		Surface: "familiar", Scope: "familiar_chat", Locale: "en",
	}); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	st, err := svc.GetState(ctx, "gcid-1", "tenant-1", "en")
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if st.MustAcknowledge {
		t.Errorf("MustAcknowledge = true, want false (acked current)")
	}
	if st.AcknowledgedVersion == nil || *st.AcknowledgedVersion != "2026-07-01" {
		t.Errorf("AcknowledgedVersion = %v", st.AcknowledgedVersion)
	}
}

func TestGetState_MaterialBump_MustReack(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", true))
	svc := aitransparency.NewService(repo, nil)
	ctx := context.Background()
	// ack old version
	if _, err := svc.Acknowledge(ctx, aitransparency.AcknowledgeParams{
		ID: "a1", GCID: "gcid-1", TenantID: "tenant-1", Version: "2026-06-01",
		Surface: "familiar", Scope: "familiar_chat", Locale: "en",
	}); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	// active is 2026-07-01 with RequiresReacknowledgement=true -> must re-ack.
	st, err := svc.GetState(ctx, "gcid-1", "tenant-1", "en")
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if !st.MustAcknowledge {
		t.Errorf("MustAcknowledge = false, want true (material bump)")
	}
}

func TestGetState_EditorialBump_NoReack(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", false)) // editorial
	svc := aitransparency.NewService(repo, nil)
	ctx := context.Background()
	if _, err := svc.Acknowledge(ctx, aitransparency.AcknowledgeParams{
		ID: "a1", GCID: "gcid-1", TenantID: "tenant-1", Version: "2026-06-01",
		Surface: "familiar", Scope: "familiar_chat", Locale: "en",
	}); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	st, err := svc.GetState(ctx, "gcid-1", "tenant-1", "en")
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if st.MustAcknowledge {
		t.Errorf("MustAcknowledge = true, want false (editorial bump serves new copy, no re-ack)")
	}
}

func TestGetState_MinorResolver_ServesMinorVariant(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", true))
	svc := aitransparency.NewService(repo, fixedAgeResolver{aitransparency.AgeSignal{
		Band: aitransparency.AgeBandMinor, Source: aitransparency.AgeSourceTenantBand,
	}})
	st, err := svc.GetState(context.Background(), "gcid-kid", "tenant-k12", "en")
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if st.Disclosure.AudienceVariant != aitransparency.VariantMinor {
		t.Errorf("variant = %q, want minor", st.Disclosure.AudienceVariant)
	}
	if st.Disclosure.Copy.Notice.Title != "Meet your Familiar" {
		t.Errorf("minor notice = %q", st.Disclosure.Copy.Notice.Title)
	}
}

func TestGetState_AgeResolverError_FailsSafeToStandard(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", true))
	svc := aitransparency.NewService(repo, errAgeResolver{})
	st, err := svc.GetState(context.Background(), "gcid-1", "tenant-1", "en")
	if err != nil {
		t.Fatalf("GetState must not fail on age-resolver error (fail-safe): %v", err)
	}
	if st.Disclosure.AudienceVariant != aitransparency.VariantStandard {
		t.Errorf("variant = %q, want standard (fail-safe)", st.Disclosure.AudienceVariant)
	}
}

// -----------------------------------------------------------------------------
// Service.Acknowledge — records minor_mode + resolves active version when blank
// -----------------------------------------------------------------------------

func TestAcknowledge_BlankVersionResolvesActive(t *testing.T) {
	repo := aitransparency.NewInMemoryRepository(seedVersion("2026-07-01", true))
	svc := aitransparency.NewService(repo, fixedAgeResolver{aitransparency.AgeSignal{
		Band: aitransparency.AgeBandMinor, Source: aitransparency.AgeSourceSelfAttestation,
	}})
	ack, err := svc.Acknowledge(context.Background(), aitransparency.AcknowledgeParams{
		ID: "a1", GCID: "gcid-1", TenantID: "tenant-1", // Version blank -> resolve active
		Surface: "familiar", Scope: "familiar_chat", Locale: "en",
	})
	if err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if ack.DisclosureVersion != "2026-07-01" {
		t.Errorf("version = %q, want active 2026-07-01", ack.DisclosureVersion)
	}
	if !ack.MinorMode {
		t.Errorf("MinorMode = false, want true (minor resolver)")
	}
}

// -----------------------------------------------------------------------------
// test doubles
// -----------------------------------------------------------------------------

type fixedAgeResolver struct{ s aitransparency.AgeSignal }

func (f fixedAgeResolver) Resolve(context.Context, string, string) (aitransparency.AgeSignal, error) {
	return f.s, nil
}

type errAgeResolver struct{}

func (errAgeResolver) Resolve(context.Context, string, string) (aitransparency.AgeSignal, error) {
	return aitransparency.AgeSignal{}, errors.New("age backend down")
}
