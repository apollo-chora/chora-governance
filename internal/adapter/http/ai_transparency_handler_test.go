package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-governance/internal/adapter/http"
	"github.com/apollo-chora/chora-governance/internal/domain/aitransparency"
)

// fakePublisher records the most recent PublishWithError call.
type fakePublisher struct {
	topic   string
	calls   int
	payload map[string]interface{}
}

func (f *fakePublisher) PublishWithError(topic string, _ govevents.Header, payload map[string]interface{}) (govevents.PublishedEvent, error) {
	f.topic = topic
	f.calls++
	f.payload = payload
	return govevents.PublishedEvent{Topic: topic}, nil
}

func seedDisclosure() *aitransparency.DisclosureVersion {
	return &aitransparency.DisclosureVersion{
		Version:                   "2026-07-01",
		Status:                    aitransparency.StatusActive,
		RequiresReacknowledgement: true,
		EffectiveFrom:             time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Scope:                     "platform",
		Locales: map[string]map[aitransparency.Variant]aitransparency.DisclosureCopy{
			"en": {
				aitransparency.VariantStandard: {
					Notice: aitransparency.NoticeCopy{Title: "Say hi to your Familiar", Body: "AI powered", Action: "Got it"},
					Badge:  aitransparency.BadgeCopy{Label: "AI companion", Tooltip: "AI can be wrong"},
					InlineLabels: aitransparency.InlineLabels{
						AiGenerated: aitransparency.LabelCopy{Label: "AI-generated", Tooltip: "Made by AI"},
					},
				},
			},
		},
	}
}

func newAITransparencyRouter(pub httpadapter.AuditPublisher) http.Handler {
	repo := aitransparency.NewInMemoryRepository(seedDisclosure())
	svc := aitransparency.NewService(repo, nil)
	return httpadapter.NewRouter(httpadapter.Deps{
		AITransparencySvc: svc,
		AuditPublisher:    pub,
	})
}

func TestAITransparency_GET_FreshLearner_MustAcknowledge(t *testing.T) {
	router := newAITransparencyRouter(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/me/ai-transparency?locale=en", nil)
	req.Header.Set("X-Tenant-Id", uuid.NewString())
	req.Header.Set("gcid", uuid.NewString())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var dto struct {
		MustAcknowledge bool   `json:"mustAcknowledge"`
		CurrentVersion  string `json:"currentVersion"`
		Disclosure      struct {
			Version         string `json:"version"`
			AudienceVariant string `json:"audienceVariant"`
			Notice          struct {
				Title  string `json:"title"`
				Action string `json:"action"`
			} `json:"notice"`
		} `json:"disclosure"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dto); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
	}
	if !dto.MustAcknowledge {
		t.Errorf("mustAcknowledge = false, want true")
	}
	if dto.CurrentVersion != "2026-07-01" {
		t.Errorf("currentVersion = %q", dto.CurrentVersion)
	}
	if dto.Disclosure.AudienceVariant != "standard" {
		t.Errorf("audienceVariant = %q, want standard", dto.Disclosure.AudienceVariant)
	}
	if dto.Disclosure.Notice.Title == "" || dto.Disclosure.Notice.Action == "" {
		t.Errorf("notice copy missing: %+v", dto.Disclosure.Notice)
	}
}

func TestAITransparency_GET_MissingHeaders_400(t *testing.T) {
	router := newAITransparencyRouter(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/me/ai-transparency", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (tenantContext gate)", rec.Code)
	}
}

func TestAITransparency_POST_Acknowledge_EmitsEventAndFlipsState(t *testing.T) {
	pub := &fakePublisher{}
	router := newAITransparencyRouter(pub)
	tenant := uuid.NewString()
	gcid := uuid.NewString()

	body, _ := json.Marshal(map[string]any{"surface": "familiar", "scope": "familiar_chat", "locale": "en"})
	req := httptest.NewRequest(http.MethodPost, "/v1/me/ai-transparency/acknowledge", bytes.NewReader(body))
	req.Header.Set("X-Tenant-Id", tenant)
	req.Header.Set("gcid", gcid)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var ack struct {
		Acknowledged      bool   `json:"acknowledged"`
		DisclosureVersion string `json:"disclosureVersion"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !ack.Acknowledged || ack.DisclosureVersion != "2026-07-01" {
		t.Errorf("ack response wrong: %+v", ack)
	}
	// Event emitted on the canonical topic.
	if pub.calls != 1 || pub.topic != govevents.TopicAiTransparencyNoticeAcknowledged {
		t.Errorf("publisher: calls=%d topic=%q", pub.calls, pub.topic)
	}
	if pub.payload["chora_imda_dimension"] != "transparency" {
		t.Errorf("envelope IMDA dimension = %v, want transparency", pub.payload["chora_imda_dimension"])
	}

	// A subsequent GET for the same learner+tenant no longer must-acknowledges.
	getReq := httptest.NewRequest(http.MethodGet, "/v1/me/ai-transparency", nil)
	getReq.Header.Set("X-Tenant-Id", tenant)
	getReq.Header.Set("gcid", gcid)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	var st struct {
		MustAcknowledge bool `json:"mustAcknowledge"`
	}
	_ = json.Unmarshal(getRec.Body.Bytes(), &st)
	if st.MustAcknowledge {
		t.Errorf("mustAcknowledge = true after acknowledge, want false")
	}
}

func TestAITransparency_POST_MissingSurfaceScope_400(t *testing.T) {
	router := newAITransparencyRouter(nil)
	body, _ := json.Marshal(map[string]any{"locale": "en"})
	req := httptest.NewRequest(http.MethodPost, "/v1/me/ai-transparency/acknowledge", bytes.NewReader(body))
	req.Header.Set("X-Tenant-Id", uuid.NewString())
	req.Header.Set("gcid", uuid.NewString())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAITransparency_GET_WrongMethod_405(t *testing.T) {
	router := newAITransparencyRouter(nil)
	req := httptest.NewRequest(http.MethodDelete, "/v1/me/ai-transparency", nil)
	req.Header.Set("X-Tenant-Id", uuid.NewString())
	req.Header.Set("gcid", uuid.NewString())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}
