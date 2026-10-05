// ai_transparency_handler.go — learner-self AI Transparency Notice endpoints
// (ADR-225 backbone). Proxied verbatim by the chora-gateway gatewayproxy
// bridge from /api/v1/me/ai-transparency[/acknowledge]; this service serves
// them at /v1/me/ai-transparency[/acknowledge] (the "/api" prefix is stripped
// by the bridge).
//
//	GET  /v1/me/ai-transparency             -> must_acknowledge + versioned copy
//	POST /v1/me/ai-transparency/acknowledge -> record evidence + emit event
//
// gcid + tenant are stamped onto the context by tenantContext (from the mesh
// headers the gateway forwards). Responses are camelCase (Angular FE consumes
// them verbatim through the pass-through bridge).
package httpadapter

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/aitransparency"
)

// aiTransparencyHandler serves the learner-self transparency endpoints.
type aiTransparencyHandler struct {
	svc       *aitransparency.Service
	publisher AuditPublisher // optional — nil disables event emission
}

// -----------------------------------------------------------------------------
// DTOs (camelCase — the FE consumes these verbatim via the gateway bridge)
// -----------------------------------------------------------------------------

type aiTransparencyDisclosureDTO struct {
	Version         string                      `json:"version"`
	Locale          string                      `json:"locale"`
	AudienceVariant string                      `json:"audienceVariant"`
	Notice          aitransparency.NoticeCopy   `json:"notice"`
	Badge           aitransparency.BadgeCopy    `json:"badge"`
	InlineLabels    aitransparency.InlineLabels `json:"inlineLabels"`
}

type aiTransparencyStateDTO struct {
	MustAcknowledge     bool                        `json:"mustAcknowledge"`
	CurrentVersion      string                      `json:"currentVersion"`
	AcknowledgedVersion *string                     `json:"acknowledgedVersion"`
	Disclosure          aiTransparencyDisclosureDTO `json:"disclosure"`
}

type acknowledgeRequestDTO struct {
	DisclosureVersion string     `json:"disclosureVersion"`
	Surface           string     `json:"surface"`
	Scope             string     `json:"scope"`
	FirstShownAt      *time.Time `json:"firstShownAt"`
	Locale            string     `json:"locale"`
}

type acknowledgeResponseDTO struct {
	Acknowledged      bool      `json:"acknowledged"`
	DisclosureVersion string    `json:"disclosureVersion"`
	AcknowledgedAt    time.Time `json:"acknowledgedAt"`
	MinorMode         bool      `json:"minorMode"`
}

// -----------------------------------------------------------------------------
// GET /v1/me/ai-transparency
// -----------------------------------------------------------------------------

func (h *aiTransparencyHandler) state(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only GET is supported on /v1/me/ai-transparency")
		return
	}
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_TRANSPARENCY_UNAVAILABLE",
			"ai-transparency service not wired")
		return
	}
	gcid := gcidFromContext(r.Context())
	tenantID := tenantFromContext(r.Context())
	locale := localeFromRequest(r)

	st, err := h.svc.GetState(r.Context(), gcid, tenantID, locale)
	if err != nil {
		log.Printf("ai-transparency state error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_TRANSPARENCY_ERROR",
			"failed to resolve transparency state")
		return
	}
	writeJSON(w, http.StatusOK, aiTransparencyStateDTO{
		MustAcknowledge:     st.MustAcknowledge,
		CurrentVersion:      st.CurrentVersion,
		AcknowledgedVersion: st.AcknowledgedVersion,
		Disclosure: aiTransparencyDisclosureDTO{
			Version:         st.Disclosure.Version,
			Locale:          st.Disclosure.Locale,
			AudienceVariant: string(st.Disclosure.AudienceVariant),
			Notice:          st.Disclosure.Copy.Notice,
			Badge:           st.Disclosure.Copy.Badge,
			InlineLabels:    st.Disclosure.Copy.InlineLabels,
		},
	})
}

// -----------------------------------------------------------------------------
// POST /v1/me/ai-transparency/acknowledge
// -----------------------------------------------------------------------------

func (h *aiTransparencyHandler) acknowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only POST is supported on /v1/me/ai-transparency/acknowledge")
		return
	}
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "GOV_TRANSPARENCY_UNAVAILABLE",
			"ai-transparency service not wired")
		return
	}
	var req acknowledgeRequestDTO
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "GOV_INVALID_BODY", err.Error())
		return
	}
	gcid := gcidFromContext(r.Context())
	tenantID := tenantFromContext(r.Context())
	surface := strings.TrimSpace(req.Surface)
	scope := strings.TrimSpace(req.Scope)
	if surface == "" || scope == "" {
		writeError(w, http.StatusBadRequest, "GOV_TRANSPARENCY_INVALID",
			"surface and scope are required")
		return
	}
	var firstShown time.Time
	if req.FirstShownAt != nil {
		firstShown = *req.FirstShownAt
	}

	ack, err := h.svc.Acknowledge(r.Context(), aitransparency.AcknowledgeParams{
		ID:           uuid.Must(uuid.NewV7()).String(),
		GCID:         gcid,
		TenantID:     tenantID,
		Version:      strings.TrimSpace(req.DisclosureVersion), // blank -> active
		Surface:      aitransparency.Surface(surface),
		Scope:        aitransparency.Scope(scope),
		FirstShownAt: firstShown,
		Locale:       strings.TrimSpace(req.Locale),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "GOV_TRANSPARENCY_INVALID", err.Error())
		return
	}

	h.emitAcknowledged(r, ack)

	writeJSON(w, http.StatusCreated, acknowledgeResponseDTO{
		Acknowledged:      true,
		DisclosureVersion: ack.DisclosureVersion,
		AcknowledgedAt:    ack.AcknowledgedAt,
		MinorMode:         ack.MinorMode,
	})
}

// emitAcknowledged publishes chora.governance.ai_transparency_notice.acknowledged.v1
// to the outbox (best-effort; the evidence row is already durable). The
// envelope is stamped with the IMDA D2 transparency dimension + runtime stage.
func (h *aiTransparencyHandler) emitAcknowledged(r *http.Request, ack *aitransparency.Acknowledgement) {
	if h.publisher == nil {
		return
	}
	payload := map[string]interface{}{
		"acknowledgement_id":   ack.ID,
		"gcid":                 ack.GCID,
		"disclosure_version":   ack.DisclosureVersion,
		"surface":              string(ack.Surface),
		"scope":                string(ack.Scope),
		"first_shown_at":       ack.FirstShownAt,
		"acknowledged_at":      ack.AcknowledgedAt,
		"locale":               ack.Locale,
		"minor_mode":           ack.MinorMode,
		"chora_imda_dimension": "transparency",
		"imda_lifecycle_stage": "runtime",
	}
	if _, err := h.publisher.PublishWithError(govevents.TopicAiTransparencyNoticeAcknowledged, govevents.Header{
		TenantID:    ack.TenantID,
		GCID:        ack.GCID,
		Traceparent: r.Header.Get("traceparent"),
	}, payload); err != nil {
		// Fail-loud in logs; do not fail the request — the acknowledgement row
		// is durably committed. Re-emit is a reconciliation concern (deferred).
		log.Printf("ai-transparency acknowledge publish: topic=%s err=%v",
			govevents.TopicAiTransparencyNoticeAcknowledged, err)
	}
}

// localeFromRequest reads the requested locale from the ?locale= query param,
// defaulting to the platform default. The disclosure resolver falls back to the
// default locale + standard variant if the requested one is absent.
func localeFromRequest(r *http.Request) string {
	loc := strings.TrimSpace(r.URL.Query().Get("locale"))
	if loc == "" {
		return aitransparency.DefaultLocale
	}
	return loc
}
