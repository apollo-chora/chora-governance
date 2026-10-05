// WeaknessAnalyzedConsumer projects the Growth-Edge analyser's terminal event
// `chora.consumption.weakness.analyzed.v1` into IMDA D2 (transparency)
// decision_explanation evidence — the governance half of the ADR-205
// Growth-Edge analyser graduation (epic CHO-1952, story CHO-1955 / WS-3).
//
// Source-of-truth:
//   - chora-contracts/proto/events/consumption/weakness.proto §WeaknessAnalyzed
//     (BINARY, Schema-Registry-bound — emitted by the ai-kernel weakness-analyser
//     crew on SUCCESSFUL multimodal analysis of an uploaded weakness document).
//   - .claude/skills/imda-governance-4-dimensions/SKILL.md (D2 routing)
//   - ADR-141 canonical IMDA dimension labels (this is `transparency` = D2).
//
// Emit-once-project-MANY: ONE analyzed.v1 event fans out into N+2
// decision_explanation rows, all imda_dimension=transparency, all with text
// lifted from the real run (integrity rule — no synthesis of a rationale the
// analyser did not produce):
//   - N learner rows         — one per real extracted edge; the verbatim
//     descriptor "summary" (else the concept_label).
//   - 1 auditor row          — the full diagnosis: model attribution
//     (model_used + token counts) + every edge with its
//     real confidence + shakiness, in "weakness" framing.
//   - 1 instructor_admin row — the same real diagnosis, instructor-framed.
//
// 3-AUDIENCE FRAMING: internal/auditor/instructor text uses the neutral
// "weakness" term (per the weakness.proto header: "The data is neutral; the
// framing is per-surface"). The learner-facing "Growth Edge" branding lives in
// the A+ FE, NOT in this governance record — so no row here carries it.
//
// Each projected row carries a DETERMINISTIC UUIDv5 event_id derived from the
// source event_id + an audience/marker discriminator, so re-delivery is
// idempotent (the evidence repo dedupes on event_id) and the rows trace back
// to the real analyzed.v1 event (provenance: upload_id -> analyzed.v1 event_id
// -> rows).
//
// NOTE on 2.3 model_card: model_used gives a model id but no version / card
// markdown, so projecting a model_card_registry row would require fabricating a
// card body — instead the real model attribution is folded VERBATIM into the
// auditor/instructor decision_explanation. 2.3 stays an honest gap (mirrors the
// AiAssistCompletedConsumer note).
//
// Cross-DB queries forbidden — chora-governance reads only its own DB; this is
// the canonical inter-domain mechanism (a Pub/Sub subscriber).
// Hexagonal: INBOUND adapter; depends only on the projector port + the shared
// derivedEventID / firstNonBlank helpers + transparencyDimension (defined in
// agent_decision_consumer.go / ai_assist_completed_consumer.go, same package).
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	consumptionv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/consumption/v1"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// TopicWeaknessAnalyzed is the canonical provisioned terminal analyser topic.
const TopicWeaknessAnalyzed = "chora.consumption.weakness.analyzed.v1"

// WeaknessAnalyzedInboxTTL is the dedupe-key retention window (matches the
// ai_assist_completed + agent_decision consumers).
const WeaknessAnalyzedInboxTTL = 24 * time.Hour

// weaknessDecisionExplanationEventType routes the projector to the
// decision_explanation aggregate (must NOT contain "model_card"/"data_card").
const weaknessDecisionExplanationEventType = "weakness.analyzed.explanation"

// WeaknessAnalyzedAttrs are the envelope-derived Pub/Sub message attributes.
// The proto envelope (field 1) is authoritative; these are a fallback for the
// case where a publisher copies envelope fields onto message attributes only.
type WeaknessAnalyzedAttrs struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	Traceparent    string
}

// WeaknessAnalyzedConsumer fans an analyzed.v1 terminal event out into D2
// transparency decision_explanation rows via the chora-governance projector.
type WeaknessAnalyzedConsumer struct {
	proj  ProjectorPort
	inbox idempotent.Store
	ttl   time.Duration
}

// NewWeaknessAnalyzedConsumer wires the projector + an idempotency inbox.
// When inbox is nil, an in-memory store is allocated.
func NewWeaknessAnalyzedConsumer(proj ProjectorPort, inbox idempotent.Store) *WeaknessAnalyzedConsumer {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &WeaknessAnalyzedConsumer{proj: proj, inbox: inbox, ttl: WeaknessAnalyzedInboxTTL}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (c *WeaknessAnalyzedConsumer) SubscribedTopic() string { return TopicWeaknessAnalyzed }

// Handle decodes one BINARY analyzed.v1 message and projects the D2 transparency
// fan-out. FAIL LOUD on decode error (NACK → DLQ); no JSON fallback. Idempotent
// on the source event_id via the inbox AND on each derived row event_id via the
// evidence repo.
func (c *WeaknessAnalyzedConsumer) Handle(ctx context.Context, body []byte, attrs WeaknessAnalyzedAttrs) error {
	if c == nil || c.proj == nil {
		return errors.New("events: WeaknessAnalyzedConsumer not initialised")
	}

	var msg consumptionv1.WeaknessAnalyzed
	if err := proto.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("events: weakness_analyzed proto decode: %w", err)
	}

	env := msg.GetEnvelope()
	eventID := firstNonBlank(env.GetEventId(), attrs.EventID)
	tenantID := firstNonBlank(env.GetTenantId(), msg.GetTenantId(), attrs.TenantID)
	// The decision owner is the learner; prefer the explicit learner_gcid field
	// (proto says it equals envelope.gcid), fall back to the envelope + attrs.
	gcid := firstNonBlank(msg.GetLearnerGcid(), env.GetGcid(), attrs.GCID)
	traceparent := firstNonBlank(env.GetTraceparent(), attrs.Traceparent)
	idempotencyKey := firstNonBlank(env.GetIdempotencyKey(), attrs.IdempotencyKey)
	uploadID := strings.TrimSpace(msg.GetUploadId())

	if strings.TrimSpace(eventID) == "" {
		return errors.New("events: weakness_analyzed envelope event_id required")
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("events: weakness_analyzed tenant_id required")
	}
	if uploadID == "" {
		return errors.New("events: weakness_analyzed upload_id required")
	}

	dedupeKey := idempotencyKey
	if dedupeKey == "" {
		dedupeKey = eventID
	}

	return c.inbox.Process(ctx, dedupeKey, c.ttl, func() error {
		rows := buildWeaknessExplanations(eventID, tenantID, gcid, traceparent, uploadID, &msg)
		for _, ev := range rows {
			if err := c.proj.Project(ctx, ev); err != nil {
				return err
			}
		}
		return nil
	})
}

// HandleEnvelope is the in-process / test convenience wrapper — the wire shape
// is a self-contained BINARY proto whose field-1 envelope is authoritative, so
// no separate attrs are needed.
func (c *WeaknessAnalyzedConsumer) HandleEnvelope(ctx context.Context, raw []byte) error {
	return c.Handle(ctx, raw, WeaknessAnalyzedAttrs{})
}

// buildWeaknessExplanations assembles the N learner + (≤1 auditor + ≤1
// instructor) decision_explanation IncomingEvents from an analyzed.v1 event.
// All text is lifted from the real run; rows with no real content are skipped
// (never fabricated).
func buildWeaknessExplanations(eventID, tenantID, gcid, traceparent, uploadID string, msg *consumptionv1.WeaknessAnalyzed) []projector.IncomingEvent {
	out := make([]projector.IncomingEvent, 0, len(msg.GetEdges())+2)

	base := func(audience, decisionID, explanation, discriminator string) projector.IncomingEvent {
		return projector.IncomingEvent{
			EventID:        derivedEventID(eventID, discriminator),
			TenantID:       tenantID,
			ImdaDimension:  transparencyDimension,
			LifecycleStage: string(evidence.LifecycleRuntime),
			EventType:      weaknessDecisionExplanationEventType,
			OccurredAt:     envelopeTime(msg.GetEnvelope().GetOccurredAt()),
			Traceparent:    traceparent,
			OwnerGcid:      gcid,
			DecisionID:     decisionID,
			Audience:       audience,
			ExplanationMD:  explanation,
		}
	}

	// Learner rows — one per real edge (verbatim summary, else concept_label).
	for i, e := range msg.GetEdges() {
		text := learnerEdgeText(e)
		if text == "" {
			continue // never fabricate a learner explanation
		}
		out = append(out, base(
			string(evidence.AudienceLearner),
			fmt.Sprintf("%s:edge:%d", uploadID, i),
			text,
			fmt.Sprintf("learner:edge:%d", i),
		))
	}

	// Auditor + instructor rows — the full diagnosis (model attribution + every
	// real edge with its confidence/shakiness). Emitted only when there is real
	// content to report (model attribution OR ≥1 usable edge) — never an empty
	// explanation.
	if diag := renderWeaknessDiagnosis(uploadID, msg.GetModelUsed(), msg.GetInputTokenCount(), msg.GetOutputTokenCount(), msg.GetEdges()); diag != "" {
		out = append(out,
			base(string(evidence.AudienceAuditor), uploadID, diag, "auditor"),
			base(string(evidence.AudienceInstructorAdmin), uploadID, diag, "instructor_admin"),
		)
	}
	return out
}

// learnerEdgeText is the verbatim learner-facing explanation for one edge: the
// descriptor "summary" if present, else the concept_label. Returns "" when the
// edge carries neither (the edge is then skipped — no fabrication).
func learnerEdgeText(e *consumptionv1.ExtractedGrowthEdge) string {
	if e == nil {
		return ""
	}
	if s := strings.TrimSpace(descriptorSummary(e.GetDescriptorJson())); s != "" {
		return s
	}
	return strings.TrimSpace(e.GetConceptLabel())
}

// descriptorSummary extracts the stable "summary" key from the edge's
// descriptor_json (one-line description of the gap). Returns "" on blank /
// malformed JSON (the caller then falls back to concept_label).
func descriptorSummary(descriptorJSON string) string {
	if strings.TrimSpace(descriptorJSON) == "" {
		return ""
	}
	var d struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal([]byte(descriptorJSON), &d); err != nil {
		return ""
	}
	return d.Summary
}

// renderWeaknessDiagnosis assembles the auditor/instructor explanation: a real
// model-attribution line + one bullet per real edge (confidence + shakiness +
// verbatim summary), in neutral "weakness" framing. Returns "" when there is
// nothing real to report (no model attribution AND no usable edge) so no row is
// fabricated.
func renderWeaknessDiagnosis(uploadID, modelUsed string, inTok, outTok int32, edges []*consumptionv1.ExtractedGrowthEdge) string {
	type usableEdge struct {
		label, summary string
		conf, strength float32
	}
	rows := make([]usableEdge, 0, len(edges))
	for _, e := range edges {
		if e == nil {
			continue
		}
		label := strings.TrimSpace(e.GetConceptLabel())
		summary := strings.TrimSpace(descriptorSummary(e.GetDescriptorJson()))
		if label == "" && summary == "" {
			continue // a blank edge carries no real content
		}
		rows = append(rows, usableEdge{label: label, summary: summary, conf: e.GetConfidence(), strength: e.GetStrength()})
	}

	model := strings.TrimSpace(modelUsed)
	hasTokens := inTok > 0 || outTok > 0
	if model == "" && !hasTokens && len(rows) == 0 {
		return "" // nothing real to report — never fabricate
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Weakness analysis of upload %s diagnosed %d weak concept(s).", strings.TrimSpace(uploadID), len(rows))

	if model != "" {
		fmt.Fprintf(&b, "\n\nModel: %s", model)
		if hasTokens {
			fmt.Fprintf(&b, " — input %d tokens, output %d tokens.", inTok, outTok)
		} else {
			b.WriteString(".")
		}
	} else if hasTokens {
		fmt.Fprintf(&b, "\n\nToken usage: input %d, output %d.", inTok, outTok)
	}

	if len(rows) == 0 {
		b.WriteString("\n\nNo weak concepts were surfaced.")
		return b.String()
	}

	b.WriteString("\n\nDiagnosed weaknesses:")
	for _, r := range rows {
		name := r.label
		if name == "" {
			name = r.summary // a label-less but summarised edge
		}
		fmt.Fprintf(&b, "\n- %s (confidence %.2f, shakiness %.2f)", name, float64(r.conf), float64(r.strength))
		if r.label != "" && r.summary != "" {
			b.WriteString(": " + r.summary)
		}
	}
	return b.String()
}
