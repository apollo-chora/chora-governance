// tail_internal_test.go — INTERNAL (package aitransparency) coverage tail:
// the unexported dedupe/dedupeVariants helpers, the full-miss ResolveCopy
// branch, NewService's nil-resolver default, resolveBand's empty-band
// branch, and Acknowledge's minor-mode stamp.
package aitransparency

import (
	"context"
	"testing"
)

func TestInternal_Dedupe_Branches(t *testing.T) {
	t.Parallel()
	if got := dedupe("", "en"); len(got) != 1 || got[0] != "en" {
		t.Errorf("empty first → %v", got)
	}
	if got := dedupe("en", "en"); len(got) != 1 {
		t.Errorf("identical → %v", got)
	}
	if got := dedupe("fr", "en"); len(got) != 2 {
		t.Errorf("distinct → %v", got)
	}
	if got := dedupeVariants("", VariantStandard); len(got) != 1 || got[0] != VariantStandard {
		t.Errorf("empty variant first → %v", got)
	}
	if got := dedupeVariants(VariantStandard, VariantStandard); len(got) != 1 {
		t.Errorf("identical variants → %v", got)
	}
	if got := dedupeVariants(VariantMinor, VariantStandard); len(got) != 2 {
		t.Errorf("distinct variants → %v", got)
	}
}

func TestInternal_ResolveCopy_TotalMiss(t *testing.T) {
	t.Parallel()
	v := &DisclosureVersion{Locales: map[string]map[Variant]DisclosureCopy{}}
	copy, loc, variant := v.ResolveCopy("fr", VariantMinor, "en")
	if loc != "" || variant != "" || copy.Notice.Title != "" {
		t.Errorf("full miss should return empty: %q %q %+v", loc, variant, copy)
	}
	// defaultLocale blank → normalized to DefaultLocale
	copy2, loc2, _ := v.ResolveCopy("", "", "")
	if loc2 != "" {
		t.Errorf("empty default: loc2=%q", loc2)
	}
	_ = copy2
}

func TestInternal_NewService_NilAgeResolverDefaults(t *testing.T) {
	t.Parallel()
	svc := NewService(NewInMemoryRepository(nil), nil)
	if svc.age == nil {
		t.Error("nil resolver should default to StandardAgeSignalResolver")
	}
	if svc.defaultLocale != DefaultLocale {
		t.Errorf("defaultLocale = %q", svc.defaultLocale)
	}
	if svc.now == nil {
		t.Error("now default missing")
	}
}

// emptyBandResolver returns a signal with an empty band → resolveBand treats
// it as unknown/none.
type emptyBandResolver struct{}

func (emptyBandResolver) Resolve(context.Context, string, string) (AgeSignal, error) {
	return AgeSignal{}, nil
}

func TestInternal_ResolveBand_EmptyBandIsUnknown(t *testing.T) {
	t.Parallel()
	svc := NewService(NewInMemoryRepository(nil), emptyBandResolver{})
	band, source := svc.resolveBand(context.Background(), "g1", "t1")
	if band != AgeBandUnknown || source != AgeSourceNone {
		t.Errorf("empty band → %q/%q; want unknown/none", band, source)
	}
}

// minorResolver returns the minor band to drive Acknowledge's MinorMode stamp.
type minorResolver struct{}

func (minorResolver) Resolve(context.Context, string, string) (AgeSignal, error) {
	return AgeSignal{Band: AgeBandMinor, Source: AgeSourceTenantBand}, nil
}

func TestInternal_Acknowledge_MinorModeStamped(t *testing.T) {
	t.Parallel()
	active := &DisclosureVersion{Version: "2026-07-01", Status: StatusActive, Scope: "platform",
		Locales: map[string]map[Variant]DisclosureCopy{"en": {VariantStandard: {
			Notice: NoticeCopy{Title: "T"}, Badge: BadgeCopy{Label: "L"},
		}}}}
	svc := NewService(NewInMemoryRepository(active), minorResolver{})
	ack, err := svc.Acknowledge(context.Background(), AcknowledgeParams{
		ID: "id-1", GCID: "g1", TenantID: "t1", Surface: "familiar", Scope: "familiar_chat",
	})
	if err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if !ack.MinorMode {
		t.Error("minor band should stamp MinorMode=true")
	}
}
