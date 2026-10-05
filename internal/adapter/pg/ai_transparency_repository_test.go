// ai_transparency_repository_test.go — pgx adapter tests for
// aitransparency.Repository using the canonical stub Querier (no live DB).
package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-governance/internal/adapter/pg"
	"github.com/apollo-chora/chora-governance/internal/domain/aitransparency"
)

func TestAiTransparency_ActiveDisclosureVersion_ParsesLocales(t *testing.T) {
	stub := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{scan: func(dest ...any) error {
				*(dest[0].(*string)) = "2026-07-01" // version
				*(dest[1].(*string)) = "active"     // status
				*(dest[2].(*bool)) = true           // requires_reack
				*(dest[3].(*time.Time)) = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				*(dest[4].(*string)) = "platform" // scope
				*(dest[5].(*string)) = `{"en":{"standard":{"notice":{"title":"Say hi","body":"b","action":"Got it"},"badge":{"label":"AI","tooltip":"t"},"inlineLabels":{"aiGenerated":{"label":"AI-generated","tooltip":"x"}}}}}`
				*(dest[6].(*string)) = "gov"  // created_by
				*(dest[7].(*string)) = "dale" // approved_by
				return nil
			}}
		},
	}
	repo := pg.NewAiTransparencyRepository(stub)
	v, err := repo.ActiveDisclosureVersion(context.Background())
	if err != nil {
		t.Fatalf("ActiveDisclosureVersion: %v", err)
	}
	if v.Version != "2026-07-01" || v.Status != aitransparency.StatusActive || !v.RequiresReacknowledgement {
		t.Errorf("bad version fields: %+v", v)
	}
	copy, loc, variant := v.ResolveCopy("en", aitransparency.VariantStandard, "en")
	if loc != "en" || variant != aitransparency.VariantStandard {
		t.Fatalf("resolve (%q,%q)", loc, variant)
	}
	if copy.Notice.Title != "Say hi" || copy.InlineLabels.AiGenerated.Label != "AI-generated" {
		t.Errorf("locales JSONB parse wrong: %+v", copy)
	}
}

func TestAiTransparency_ActiveDisclosureVersion_NoRows(t *testing.T) {
	stub := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: pg.ErrNoRows}
		},
	}
	repo := pg.NewAiTransparencyRepository(stub)
	_, err := repo.ActiveDisclosureVersion(context.Background())
	if !errors.Is(err, aitransparency.ErrNoActiveDisclosure) {
		t.Errorf("err = %v, want ErrNoActiveDisclosure", err)
	}
}

func TestAiTransparency_LatestAcknowledgement_ScopesTenantAndScans(t *testing.T) {
	tenant := uuid.NewString()
	gcid := uuid.NewString()
	stub := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{scan: func(dest ...any) error {
				*(dest[0].(*string)) = uuid.NewString() // id
				*(dest[1].(*string)) = tenant           // tenant_id
				*(dest[2].(*string)) = gcid             // gcid
				*(dest[3].(*string)) = "2026-07-01"     // disclosure_version
				*(dest[4].(*string)) = "familiar"       // surface
				*(dest[5].(*string)) = "familiar_chat"  // scope
				*(dest[6].(*time.Time)) = time.Now()    // first_shown_at
				*(dest[7].(*time.Time)) = time.Now()    // acknowledged_at
				*(dest[8].(*string)) = "en"             // locale
				*(dest[9].(*bool)) = false              // minor_mode
				*(dest[10].(*time.Time)) = time.Now()   // created_at
				return nil
			}}
		},
	}
	repo := pg.NewAiTransparencyRepository(stub)
	got, err := repo.LatestAcknowledgement(context.Background(), gcid, tenant)
	if err != nil {
		t.Fatalf("LatestAcknowledgement: %v", err)
	}
	if got.DisclosureVersion != "2026-07-01" || got.Surface != "familiar" || got.Scope != "familiar_chat" {
		t.Errorf("scan wrong: %+v", got)
	}
	if !stub.txCalled || stub.txTenantID != tenant {
		t.Errorf("RLS GUC not applied: txCalled=%v txTenantID=%q want %q", stub.txCalled, stub.txTenantID, tenant)
	}
}

func TestAiTransparency_LatestAcknowledgement_NotFound(t *testing.T) {
	stub := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row {
			return &stubRow{err: pg.ErrNoRows}
		},
	}
	repo := pg.NewAiTransparencyRepository(stub)
	_, err := repo.LatestAcknowledgement(context.Background(), uuid.NewString(), uuid.NewString())
	if !errors.Is(err, aitransparency.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestAiTransparency_LatestAcknowledgement_PlatformTenantNormalised(t *testing.T) {
	stub := &stubQuerier{
		queryRowFn: func(_ string, _ ...any) pg.Row { return &stubRow{err: pg.ErrNoRows} },
	}
	repo := pg.NewAiTransparencyRepository(stub)
	_, _ = repo.LatestAcknowledgement(context.Background(), uuid.NewString(), "platform")
	if stub.txTenantID != pg.NilTenantUUID {
		t.Errorf("platform tenant not normalised: got %q want %q", stub.txTenantID, pg.NilTenantUUID)
	}
}

func TestAiTransparency_AppendAcknowledgement_InsertIdempotentAndScoped(t *testing.T) {
	tenant := uuid.NewString()
	ack, err := aitransparency.NewAcknowledgement(aitransparency.AcknowledgeParams{
		ID: uuid.NewString(), GCID: uuid.NewString(), TenantID: tenant, Version: "2026-07-01",
		Surface: "familiar", Scope: "familiar_chat", Locale: "en", MinorMode: true,
	})
	if err != nil {
		t.Fatalf("NewAcknowledgement: %v", err)
	}
	stub := &stubQuerier{}
	repo := pg.NewAiTransparencyRepository(stub)
	if err := repo.AppendAcknowledgement(context.Background(), ack); err != nil {
		t.Fatalf("AppendAcknowledgement: %v", err)
	}
	if !stub.txCalled || stub.txTenantID != tenant {
		t.Errorf("RLS GUC not applied: txCalled=%v txTenantID=%q", stub.txCalled, stub.txTenantID)
	}
	if !strings.Contains(stub.execSQL, "ON CONFLICT (tenant_id, gcid, disclosure_version) DO NOTHING") {
		t.Errorf("insert not idempotent: %q", stub.execSQL)
	}
	if !strings.Contains(stub.execSQL, "INSERT INTO ai_transparency_acknowledgement") {
		t.Errorf("wrong table: %q", stub.execSQL)
	}
}

func TestAiTransparency_AppendAcknowledgement_Nil(t *testing.T) {
	repo := pg.NewAiTransparencyRepository(&stubQuerier{})
	if err := repo.AppendAcknowledgement(context.Background(), nil); err == nil {
		t.Errorf("expected error on nil ack")
	}
}
