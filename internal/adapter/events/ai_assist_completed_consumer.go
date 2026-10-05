// AiAssistCompletedConsumer projects the EXISTING terminal qgen event
// `chora.creation.ai_assist.completed.v1` into IMDA D2 (transparency)
// decision_explanation evidence — the D2 half of the O+ golden evidence
// pipeline (ADR-173, CHO-1641).
//
// Source-of-truth:
//   - chora-contracts/proto/events/creation/ai_assist.proto §AiAssistCompleted
//     (BINARY, Schema-Registry-bound — published by the orchestrator outbox
//     via services/chora-ai-kernel-orchestrator qgen_crew_publisher.publish_completed)
//   - .claude/skills/imda-governance-4-dimensions/SKILL.md (D2 routing)
//   - docs/HANDOFF_OPLUS_RUBRIC_D2D4_GOLDEN_PIPELINE_2026-06-02.md §4 (Approach B)
//
// Emit-once-project-MANY: ONE completed.v1 event fans out into N+2
// decision_explanation rows, all imda_dimension=transparency, all with text
// lifted VERBATIM from the real run (integrity rule — no synthesis):
//   - N learner rows   — one per real MCQ option `explainer` (2.2 source_attribution)
//   - 1 auditor row    — the real critic diagnosis (critic_notes + pipeline_trace)
//   - 1 instructor_admin row — the same real reasoning, instructor-framed
//
// (2.1 explainability counts ALL decision_explanation rows.)
//
// Each projected row carries a DETERMINISTIC UUIDv5 event_id derived from the
// source event_id + an audience/marker discriminator, so re-delivery is
// idempotent (the evidence repo dedupes on event_id) and the rows trace back
// to the real completed.v1 event (provenance: assist_id -> completed.v1
// event_id -> rows).
//
// NOTE on 2.3 model_card: the publisher does NOT populate AiAssistCompleted
// .model_used (verified), so no honest model_card can be projected from this
// event. 2.3 (model_version_tracking) is P3 and stays an honest gap.
//
// Cross-DB queries forbidden — chora-governance reads only its own DB.
// Hexagonal: this is an INBOUND adapter; depends only on the projector port.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	creationv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/creation/v1"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// TopicAiAssistCompleted is the canonical provisioned terminal qgen topic.
const TopicAiAssistCompleted = "chora.creation.ai_assist.completed.v1"

// AiAssistCompletedInboxTTL is the dedupe-key retention window (matches the
// agent_decision consumer).
const AiAssistCompletedInboxTTL = 24 * time.Hour

// transparencyDimension is the canonical D2 IMDA dimension (ADR-141) this
// consumer stamps on every projected row. The source completed.v1 is a
// creation-domain event whose envelope leaves chora_imda_dimension blank;
// the transparency framing is this projector's responsibility.
const transparencyDimension = "transparency"

// decisionExplanationEventType routes the projector to the
// decision_explanation aggregate (must NOT contain "model_card"/"data_card").
const decisionExplanationEventType = "ai_assist.completed.explanation"

// derivedIDNamespace is the fallback UUIDv5 namespace used when the source
// event_id is not itself a parseable UUID (it always is in practice — the
// envelope event_id is UUIDv7). Fixed so derivation stays deterministic.
var derivedIDNamespace = uuid.MustParse("6f3c1e2a-0d4b-7a9c-8e10-c0ffee000d22")

// AiAssistCompletedAttrs are the envelope-derived Pub/Sub message attributes.
// The orchestrator outbox copies envelope fields onto message attributes; the
// consumer prefers the proto envelope and falls back to these.
type AiAssistCompletedAttrs struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	Traceparent    string
}

// AiAssistCompletedConsumer fans a completed.v1 terminal event out into D2
// transparency decision_explanation rows via the chora-governance projector.
type AiAssistCompletedConsumer struct {
	proj  ProjectorPort
	inbox idempotent.Store
	ttl   time.Duration

	mu sync.Mutex
}

// NewAiAssistCompletedConsumer wires the projector + an idempotency inbox.
// When inbox is nil, an in-memory store is allocated.
func NewAiAssistCompletedConsumer(proj ProjectorPort, inbox idempotent.Store) *AiAssistCompletedConsumer {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &AiAssistCompletedConsumer{proj: proj, inbox: inbox, ttl: AiAssistCompletedInboxTTL}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (c *AiAssistCompletedConsumer) SubscribedTopic() string { return TopicAiAssistCompleted }

// Handle decodes one BINARY completed.v1 message and projects the D2
// transparency fan-out. FAIL LOUD on decode error (NACK → DLQ); no JSON
// fallback. Idempotent on the source event_id via the inbox AND on each
// derived row event_id via the evidence repo.
func (c *AiAssistCompletedConsumer) Handle(ctx context.Context, body []byte, attrs AiAssistCompletedAttrs) error {
	if c == nil || c.proj == nil {
		return errors.New("events: AiAssistCompletedConsumer not initialised")
	}

	var msg creationv1.AiAssistCompleted
	if err := proto.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("events: ai_assist_completed proto decode: %w", err)
	}

	env := msg.GetEnvelope()
	eventID := firstNonBlank(env.GetEventId(), attrs.EventID)
	tenantID := firstNonBlank(env.GetTenantId(), attrs.TenantID)
	gcid := firstNonBlank(env.GetGcid(), attrs.GCID)
	traceparent := firstNonBlank(env.GetTraceparent(), attrs.Traceparent)
	idempotencyKey := firstNonBlank(env.GetIdempotencyKey(), attrs.IdempotencyKey)
	assistID := strings.TrimSpace(msg.GetAssistId())

	if strings.TrimSpace(eventID) == "" {
		return errors.New("events: ai_assist_completed envelope event_id required")
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("events: ai_assist_completed envelope tenant_id required")
	}
	if assistID == "" {
		return errors.New("events: ai_assist_completed assist_id required")
	}

	dedupeKey := idempotencyKey
	if dedupeKey == "" {
		dedupeKey = eventID
	}

	return c.inbox.Process(ctx, dedupeKey, c.ttl, func() error {
		rows := buildDecisionExplanations(eventID, tenantID, gcid, traceparent, assistID, &msg)
		for _, ev := range rows {
			if err := c.proj.Project(ctx, ev); err != nil {
				return err
			}
		}
		return nil
	})
}

// HandleEnvelope is the in-process / test convenience wrapper — the wire
// shape is a self-contained BINARY proto whose field-1 envelope is
// authoritative, so no separate attrs are needed.
func (c *AiAssistCompletedConsumer) HandleEnvelope(ctx context.Context, raw []byte) error {
	return c.Handle(ctx, raw, AiAssistCompletedAttrs{})
}

// buildDecisionExplanations assembles the N learner + (≤1 auditor + ≤1
// instructor) decision_explanation IncomingEvents from a completed.v1 event.
// All text is lifted verbatim from the real run; rows with no real content
// are skipped (never fabricated).
func buildDecisionExplanations(eventID, tenantID, gcid, traceparent, assistID string, msg *creationv1.AiAssistCompleted) []projector.IncomingEvent {
	out := make([]projector.IncomingEvent, 0, 6)

	base := func(audience, decisionID, explanation, discriminator string) projector.IncomingEvent {
		return projector.IncomingEvent{
			EventID:        derivedEventID(eventID, discriminator),
			TenantID:       tenantID,
			ImdaDimension:  transparencyDimension,
			LifecycleStage: string(evidence.LifecycleRuntime),
			EventType:      decisionExplanationEventType,
			OccurredAt:     envelopeTime(msg.GetEnvelope().GetOccurredAt()),
			Traceparent:    traceparent,
			OwnerGcid:      gcid,
			DecisionID:     decisionID,
			Audience:       audience,
			ExplanationMD:  explanation,
		}
	}

	// Learner rows — one per real MCQ option explainer (2.2 source_attribution).
	for i, opt := range parseMCQOptions(msg.GetCandidatePayloadJson()) {
		explainer := strings.TrimSpace(opt.Explainer)
		if explainer == "" {
			continue // never fabricate a rationale
		}
		marker := optionMarker(i)
		out = append(out, base(
			string(evidence.AudienceLearner),
			fmt.Sprintf("%s:opt:%s", assistID, marker),
			explainer,
			"learner:"+marker,
		))
	}

	// Auditor + instructor rows — the real critic diagnosis (verbatim).
	if reasoning := renderCriticExplanation(msg.GetCriticNotes(), msg.GetPipelineTraceJson()); reasoning != "" {
		out = append(out,
			base(string(evidence.AudienceAuditor), assistID, reasoning, "auditor"),
			base(string(evidence.AudienceInstructorAdmin), assistID, reasoning, "instructor_admin"),
		)
	}
	return out
}

// wireOption is the minimal projection of the candidate MCQ option JSON
// (mirrors chora-creation's candidate_normalizer wireMCQOption).
type wireOption struct {
	Label     string `json:"label"`
	Explainer string `json:"explainer"`
}

// parseMCQOptions extracts MCQ options from candidate_payload_json, handling
// both the top-level `options` and the nested `mcq_payload.options` shapes.
func parseMCQOptions(candidateJSON string) []wireOption {
	if strings.TrimSpace(candidateJSON) == "" {
		return nil
	}
	var cand struct {
		Options    []wireOption `json:"options"`
		MCQPayload struct {
			Options []wireOption `json:"options"`
		} `json:"mcq_payload"`
	}
	if err := json.Unmarshal([]byte(candidateJSON), &cand); err != nil {
		return nil // malformed candidate → no learner rows (auditor still emits)
	}
	if len(cand.Options) > 0 {
		return cand.Options
	}
	return cand.MCQPayload.Options
}

// renderCriticExplanation assembles the auditor/instructor explanation from
// the real critic_notes + pipeline_trace rows. Returns "" when neither
// carries content (so no row is fabricated).
func renderCriticExplanation(criticNotes, traceJSON string) string {
	var parts []string
	if n := strings.TrimSpace(criticNotes); n != "" {
		parts = append(parts, n)
	}
	if traceLines := renderTrace(traceJSON); traceLines != "" {
		parts = append(parts, traceLines)
	}
	return strings.Join(parts, "\n\n")
}

// renderTrace renders the real pipeline_trace rows ({name,status,notes}) as a
// markdown list (verbatim notes). Returns "" when no row carries a note.
func renderTrace(traceJSON string) string {
	if strings.TrimSpace(traceJSON) == "" {
		return ""
	}
	var rows []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Notes  string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(traceJSON), &rows); err != nil {
		return ""
	}
	var lines []string
	for _, r := range rows {
		if strings.TrimSpace(r.Notes) == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("- %s (%s): %s", r.Name, r.Status, strings.TrimSpace(r.Notes)))
	}
	if len(lines) == 0 {
		return ""
	}
	return "Pipeline trace:\n" + strings.Join(lines, "\n")
}

// derivedEventID produces a deterministic UUIDv5 from the source event_id +
// discriminator so each projected row has a stable, distinct event_id (idempotent
// re-delivery; provenance to the source event).
func derivedEventID(sourceEventID, discriminator string) string {
	ns := derivedIDNamespace
	if parsed, err := uuid.Parse(strings.TrimSpace(sourceEventID)); err == nil {
		ns = parsed
	}
	return uuid.NewSHA1(ns, []byte(discriminator)).String()
}

// optionMarker maps a 0-based option index to its positional marker (A/B/C…),
// falling back to a 1-based number past Z (per feedback_mcq_option_naming —
// marker is positional + auto-computed + never stored).
func optionMarker(i int) string {
	if i >= 0 && i < 26 {
		return string(rune('A' + i))
	}
	return fmt.Sprintf("%d", i+1)
}
