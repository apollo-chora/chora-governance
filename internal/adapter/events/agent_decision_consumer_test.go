// Tests for the AgentDecisionConsumer per Acceptance Gate #8 of
// OE-AI-ASSIST + ADR-167 Phase 2 (JSON→Protobuf wire-format migration).
//
// Wire shape (ADR-167): the Pub/Sub message `data` is a binary-protobuf
// `chora.observability.v1.AgentDecisionLogged` (envelope @ field 1 is the
// AUTHORITATIVE envelope). Fixtures here marshal a real generated proto
// message via proto.Marshal and feed the bytes to the consumer — exactly
// the bytes the broker would deliver post-cutover. The malformed-bytes
// case asserts the fail-loud DLQ path (proto.Unmarshal error → NACK).
package events_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	observabilityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/observability/v1"

	"github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

const (
	adlTestTenantID    = "01970000-0000-7000-8000-0000000000aa"
	adlTestGCID        = "01970000-0000-7000-8000-0000000000bb"
	adlTestAssistID    = "01970000-0000-7000-8000-0000000000cc"
	adlTestEventID     = "01970000-0000-7000-8000-0000000000dd"
	adlTestTrace       = "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"
	adlTestTracestate  = "vendor=test"
	adlTestIdempotency = "ai_assist.decision.job-1"
)

var adlTestOccurredAt = time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC)

// newAttrs builds the routing-attribute copies that travel on the Pub/Sub
// message. Post-ADR-167 the proto envelope (field 1) is canonical; attrs
// are only a fallback when the proto envelope is absent.
func newAttrs() events.AgentDecisionEnvelopeAttrs {
	return events.AgentDecisionEnvelopeAttrs{
		EventID:            adlTestEventID,
		IdempotencyKey:     adlTestIdempotency,
		TenantID:           adlTestTenantID,
		GCID:               adlTestGCID,
		Traceparent:        adlTestTrace,
		Tracestate:         adlTestTracestate,
		ChoraImdaDimension: "accountability",
		SchemaVersion:      "1",
		CrewName:           "mcq_ai_assist",
	}
}

// fixedDecisionProto builds a canonical AgentDecisionLogged proto per the
// ADR-167 qgen⇄AgentDecisionLogged mapping. `decision` is the qgen verdict
// string carried in the attributes map.
func fixedDecisionProto(decision string) *observabilityv1.AgentDecisionLogged {
	return &observabilityv1.AgentDecisionLogged{
		Envelope: &commonv1.EventEnvelope{
			EventId:            adlTestEventID,
			IdempotencyKey:     adlTestIdempotency,
			TenantId:           adlTestTenantID,
			Gcid:               adlTestGCID,
			OccurredAt:         timestamppb.New(adlTestOccurredAt),
			Traceparent:        adlTestTrace,
			Tracestate:         adlTestTracestate,
			SchemaVersion:      1,
			ChoraImdaDimension: "accountability",
		},
		DecisionId:       adlTestAssistID,
		InvocationId:     adlTestAssistID,
		Agid:             "qgen_question",
		DecisionKind:     observabilityv1.DecisionKind_DECISION_KIND_CRITIQUE,
		OutputSummary:    "stem ambiguous on attempt 2",
		DecidedAt:        timestamppb.New(adlTestOccurredAt),
		CrewName:         "mcq_ai_assist",
		CrewId:           adlTestAssistID,
		GuardrailOutcome: "pass",
		PromptTokens:     180,
		CompletionTokens: 100,
		CachedTokens:     15,
		Attributes: map[string]string{
			"decision":        decision,
			"attempt_count":   "2",
			"max_retries":     "3",
			"quality_warning": "false",
		},
	}
}

func newPayload(t *testing.T, decision string) []byte {
	t.Helper()
	b, err := proto.Marshal(fixedDecisionProto(decision))
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

// marshalProto is a brief helper for the variant fixtures.
func marshalProto(t *testing.T, m *observabilityv1.AgentDecisionLogged) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestAgentDecisionConsumer_HappyPath_Accepted(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	if err := sub.Handle(context.Background(), newPayload(t, "accepted"), newAttrs()); err != nil {
		t.Fatalf("handle: %v", err)
	}

	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1 projection; got %d", len(rec))
	}
	got := rec[0]
	if got.EventID != adlTestEventID {
		t.Fatalf("EventID = %q; want %q", got.EventID, adlTestEventID)
	}
	if got.TenantID != adlTestTenantID {
		t.Fatalf("TenantID = %q; want %q", got.TenantID, adlTestTenantID)
	}
	if got.OwnerGcid != adlTestGCID {
		t.Fatalf("OwnerGcid = %q; want %q", got.OwnerGcid, adlTestGCID)
	}
	if got.DecisionID != adlTestAssistID {
		t.Fatalf("DecisionID = %q; want %q (assist_id)", got.DecisionID, adlTestAssistID)
	}
	// AgentID must be the REAL agid from the inbound event (proto field 4),
	// NOT a hardcoded crew label. The fixture uses the per-agent agid
	// "qgen_question"; the projection must pass it through verbatim.
	if got.AgentID != "qgen_question" {
		t.Fatalf("AgentID = %q; want %q (real agid passthrough)", got.AgentID, "qgen_question")
	}
	if got.DecisionType != "qgen.quality_gate.accepted" {
		t.Fatalf("DecisionType = %q; want %q", got.DecisionType, "qgen.quality_gate.accepted")
	}
	if got.ImdaDimension != "accountability" {
		t.Fatalf("ImdaDimension = %q; want %q", got.ImdaDimension, "accountability")
	}
	if got.Traceparent != adlTestTrace {
		t.Fatalf("Traceparent = %q; want %q", got.Traceparent, adlTestTrace)
	}
	// Provenance carries the rich decision context (sourced from the
	// attributes map + output_summary + envelope per ADR-167 mapping).
	if got.Provenance["assist_id"] != adlTestAssistID {
		t.Fatalf("provenance.assist_id = %v", got.Provenance["assist_id"])
	}
	if got.Provenance["decision"] != "accepted" {
		t.Fatalf("provenance.decision = %v", got.Provenance["decision"])
	}
	if got.Provenance["attempt_count"] != 2 {
		t.Fatalf("provenance.attempt_count = %v (want 2)", got.Provenance["attempt_count"])
	}
	if got.Provenance["max_retries"] != 3 {
		t.Fatalf("provenance.max_retries = %v (want 3)", got.Provenance["max_retries"])
	}
	if got.Provenance["quality_warning"] != false {
		t.Fatalf("provenance.quality_warning = %v (want false)", got.Provenance["quality_warning"])
	}
	if got.Provenance["critic_notes"] != "stem ambiguous on attempt 2" {
		t.Fatalf("provenance.critic_notes = %v", got.Provenance["critic_notes"])
	}
	// occurred_at sourced from decided_at (proto Timestamp → RFC3339).
	if got.Provenance["occurred_at"] != adlTestOccurredAt.Format(time.RFC3339Nano) {
		t.Fatalf("provenance.occurred_at = %v", got.Provenance["occurred_at"])
	}
	if got.Provenance["tracestate"] != adlTestTracestate {
		t.Fatalf("provenance.tracestate = %v", got.Provenance["tracestate"])
	}
	if got.Provenance["crew_name"] != "mcq_ai_assist" {
		t.Fatalf("provenance.crew_name = %v (want mcq_ai_assist)", got.Provenance["crew_name"])
	}
	if got.Provenance["crew_id"] != adlTestAssistID {
		t.Fatalf("provenance.crew_id = %v (want assist_id)", got.Provenance["crew_id"])
	}
	if got.Provenance["guardrail_outcome"] != "pass" {
		t.Fatalf("provenance.guardrail_outcome = %v", got.Provenance["guardrail_outcome"])
	}
	if got.Provenance["prompt_tokens"] != int64(180) {
		t.Fatalf("provenance.prompt_tokens = %v (want 180)", got.Provenance["prompt_tokens"])
	}
	if got.Provenance["completion_tokens"] != int64(100) {
		t.Fatalf("provenance.completion_tokens = %v (want 100)", got.Provenance["completion_tokens"])
	}
	if got.Provenance["cached_tokens"] != int64(15) {
		t.Fatalf("provenance.cached_tokens = %v (want 15)", got.Provenance["cached_tokens"])
	}
}

func TestAgentDecisionConsumer_ProtoEnvelopeIsCanonical(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	// Proto envelope (field 1) is the authoritative source. Even if the
	// routing attrs disagree, the proto envelope wins.
	m := fixedDecisionProto("accepted")
	attrs := newAttrs()
	attrs.TenantID = "stale-tenant-from-attrs"
	attrs.GCID = "stale-gcid-from-attrs"
	attrs.Traceparent = "00-stale0000000000000000000000000000-stale00000000000-01"

	if err := sub.Handle(context.Background(), marshalProto(t, m), attrs); err != nil {
		t.Fatalf("handle: %v", err)
	}
	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1; got %d", len(rec))
	}
	if rec[0].TenantID != adlTestTenantID {
		t.Fatalf("proto envelope tenant_id should win; got %q", rec[0].TenantID)
	}
	if rec[0].OwnerGcid != adlTestGCID {
		t.Fatalf("proto envelope gcid should win; got %q", rec[0].OwnerGcid)
	}
	if rec[0].Traceparent != adlTestTrace {
		t.Fatalf("proto envelope traceparent should win; got %q", rec[0].Traceparent)
	}
}

func TestAgentDecisionConsumer_FallsBackToAttrsWhenProtoEnvelopeAbsent(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	// Proto with NO envelope — consumer must fall back to routing attrs
	// for the envelope-mandatory fields.
	m := &observabilityv1.AgentDecisionLogged{
		DecisionId:   adlTestAssistID,
		InvocationId: adlTestAssistID,
		Agid:         "qgen_crew",
		DecisionKind: observabilityv1.DecisionKind_DECISION_KIND_CRITIQUE,
		Attributes:   map[string]string{"decision": "accepted"},
	}
	if err := sub.Handle(context.Background(), marshalProto(t, m), newAttrs()); err != nil {
		t.Fatalf("handle: %v", err)
	}
	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1; got %d", len(rec))
	}
	if rec[0].TenantID != adlTestTenantID {
		t.Fatalf("attrs tenant_id fallback; got %q", rec[0].TenantID)
	}
	if rec[0].EventID != adlTestEventID {
		t.Fatalf("attrs event_id fallback; got %q", rec[0].EventID)
	}
}

func TestAgentDecisionConsumer_ExtensionFieldsForwarded(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	m := fixedDecisionProto("accepted")
	m.IsResume = true
	m.IsEvalRun = true
	m.AdapterVersion = "lora-tenant-acme-v3"
	m.GuardrailOutcome = "block"
	m.PromptTokens = 42
	m.CompletionTokens = 17
	m.CachedTokens = 3

	if err := sub.Handle(context.Background(), marshalProto(t, m), newAttrs()); err != nil {
		t.Fatalf("handle: %v", err)
	}
	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1; got %d", len(rec))
	}
	prov := rec[0].Provenance
	if prov["is_resume"] != true {
		t.Fatalf("provenance.is_resume = %v", prov["is_resume"])
	}
	if prov["is_eval_run"] != true {
		t.Fatalf("provenance.is_eval_run = %v", prov["is_eval_run"])
	}
	if prov["adapter_version"] != "lora-tenant-acme-v3" {
		t.Fatalf("provenance.adapter_version = %v", prov["adapter_version"])
	}
	if prov["guardrail_outcome"] != "block" {
		t.Fatalf("provenance.guardrail_outcome = %v", prov["guardrail_outcome"])
	}
	if prov["prompt_tokens"] != int64(42) {
		t.Fatalf("provenance.prompt_tokens = %v", prov["prompt_tokens"])
	}
	if prov["completion_tokens"] != int64(17) {
		t.Fatalf("provenance.completion_tokens = %v", prov["completion_tokens"])
	}
	if prov["cached_tokens"] != int64(3) {
		t.Fatalf("provenance.cached_tokens = %v", prov["cached_tokens"])
	}
}

func TestAgentDecisionConsumer_DecisionVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		decision string
		want     string
	}{
		{"accepted", "qgen.quality_gate.accepted"},
		{"retry", "qgen.quality_gate.retry"},
		{"completed_with_warning", "qgen.quality_gate.completed_with_warning"},
		{"rejected", "qgen.quality_gate.rejected"},
		{"refused", "qgen.quality_gate.refused"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.decision, func(t *testing.T) {
			t.Parallel()
			proj := events.NewInMemoryProjector()
			sub := events.NewAgentDecisionConsumer(proj, nil)

			m := fixedDecisionProto(tc.decision)
			// Distinct event_id per case to avoid the in-memory
			// idempotency store deduping.
			m.Envelope.EventId = adlTestEventID + "-" + tc.decision
			m.Envelope.IdempotencyKey = adlTestIdempotency + "-" + tc.decision
			attrs := newAttrs()
			attrs.EventID = m.Envelope.EventId
			attrs.IdempotencyKey = m.Envelope.IdempotencyKey

			if err := sub.Handle(context.Background(), marshalProto(t, m), attrs); err != nil {
				t.Fatalf("handle: %v", err)
			}
			rec := proj.Recorded()
			if len(rec) != 1 {
				t.Fatalf("expected 1 projection; got %d", len(rec))
			}
			if rec[0].DecisionType != tc.want {
				t.Fatalf("DecisionType = %q; want %q", rec[0].DecisionType, tc.want)
			}
		})
	}
}

func TestAgentDecisionConsumer_DedupesByIdempotencyKey(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	attrs := newAttrs()
	body := newPayload(t, "accepted")

	if err := sub.Handle(context.Background(), body, attrs); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if err := sub.Handle(context.Background(), body, attrs); err != nil {
		t.Fatalf("second handle: %v", err)
	}

	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1 projection (idempotent); got %d", len(rec))
	}
}

func TestAgentDecisionConsumer_DedupesByEventIDWhenIdempotencyKeyEmpty(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	m := fixedDecisionProto("accepted")
	m.Envelope.IdempotencyKey = "" // Force fallback to event_id.
	attrs := newAttrs()
	attrs.IdempotencyKey = ""
	body := marshalProto(t, m)

	if err := sub.Handle(context.Background(), body, attrs); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if err := sub.Handle(context.Background(), body, attrs); err != nil {
		t.Fatalf("second handle: %v", err)
	}

	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1 projection (idempotent via event_id); got %d", len(rec))
	}
}

func TestAgentDecisionConsumer_RejectsMissingEventID(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	m := fixedDecisionProto("accepted")
	m.Envelope.EventId = ""
	attrs := newAttrs()
	attrs.EventID = ""
	err := sub.Handle(context.Background(), marshalProto(t, m), attrs)
	if err == nil || !strings.Contains(err.Error(), "event_id") {
		t.Fatalf("expected event_id required error; got %v", err)
	}
}

func TestAgentDecisionConsumer_RejectsMissingTenantID(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	m := fixedDecisionProto("accepted")
	m.Envelope.TenantId = ""
	attrs := newAttrs()
	attrs.TenantID = ""
	err := sub.Handle(context.Background(), marshalProto(t, m), attrs)
	if err == nil || !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("expected tenant_id required error; got %v", err)
	}
}

func TestAgentDecisionConsumer_RejectsMissingAssistID(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	m := fixedDecisionProto("accepted")
	m.DecisionId = ""
	m.InvocationId = ""
	err := sub.Handle(context.Background(), marshalProto(t, m), newAttrs())
	if err == nil || !strings.Contains(err.Error(), "assist_id") {
		t.Fatalf("expected assist_id required error; got %v", err)
	}
}

func TestAgentDecisionConsumer_RejectsMissingDecision(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	m := fixedDecisionProto("accepted")
	m.Attributes = map[string]string{} // no "decision" key
	err := sub.Handle(context.Background(), marshalProto(t, m), newAttrs())
	if err == nil || !strings.Contains(err.Error(), "decision") {
		t.Fatalf("expected decision required error; got %v", err)
	}
}

func TestAgentDecisionConsumer_RejectsUnexpectedDimension(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	m := fixedDecisionProto("accepted")
	m.Envelope.ChoraImdaDimension = "safety_and_robustness"
	attrs := newAttrs()
	attrs.ChoraImdaDimension = "safety_and_robustness"
	err := sub.Handle(context.Background(), marshalProto(t, m), attrs)
	if err == nil || !strings.Contains(err.Error(), "imda_dimension") {
		t.Fatalf("expected imda_dimension validation error; got %v", err)
	}
}

// TestAgentDecisionConsumer_RejectsMalformedProto asserts the FAIL-LOUD
// DLQ path (ADR-167 HARD REQUIREMENT #1): non-protobuf bytes → error →
// NACK → DLQ. NO JSON fallback.
func TestAgentDecisionConsumer_RejectsMalformedProto(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	// Bytes that are neither valid AgentDecisionLogged proto nor JSON the
	// consumer would silently accept. A high field-tag with bad length
	// triggers proto.Unmarshal error.
	err := sub.Handle(context.Background(), []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, newAttrs())
	if err == nil {
		t.Fatalf("expected proto decode error; got nil")
	}
	if !strings.Contains(err.Error(), "proto") && !strings.Contains(err.Error(), "decode") {
		t.Fatalf("expected proto/decode error; got %v", err)
	}
	if len(proj.Recorded()) != 0 {
		t.Fatalf("malformed proto must not project; got %d", len(proj.Recorded()))
	}
}

func TestAgentDecisionConsumer_PropagatesProjectorError(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	proj.SetFailNext(true, errors.New("repo down"))
	sub := events.NewAgentDecisionConsumer(proj, nil)

	err := sub.Handle(context.Background(), newPayload(t, "accepted"), newAttrs())
	if err == nil || !strings.Contains(err.Error(), "repo down") {
		t.Fatalf("expected projector error to propagate; got %v", err)
	}
}

func TestAgentDecisionConsumer_NilSubscriber(t *testing.T) {
	t.Parallel()
	var sub *events.AgentDecisionConsumer // nil receiver
	err := sub.Handle(context.Background(), newPayload(t, "accepted"), newAttrs())
	if err == nil || !strings.Contains(err.Error(), "not initialised") {
		t.Fatalf("expected not-initialised error; got %v", err)
	}
}

func TestAgentDecisionConsumer_UninitialisedProjector(t *testing.T) {
	t.Parallel()
	sub := events.NewAgentDecisionConsumer(nil, nil)
	err := sub.Handle(context.Background(), newPayload(t, "accepted"), newAttrs())
	if err == nil || !strings.Contains(err.Error(), "not initialised") {
		t.Fatalf("expected not-initialised error; got %v", err)
	}
}

func TestAgentDecisionConsumer_SubscribedTopic(t *testing.T) {
	t.Parallel()
	if events.TopicAgentDecisionLogged != "chora.observability.agent_decision.logged.v1" {
		t.Fatalf("topic constant drifted: %q", events.TopicAgentDecisionLogged)
	}
	sub := events.NewAgentDecisionConsumer(events.NewInMemoryProjector(), nil)
	if got := sub.SubscribedTopic(); got != events.TopicAgentDecisionLogged {
		t.Fatalf("SubscribedTopic = %q; want %q", got, events.TopicAgentDecisionLogged)
	}
}

func TestAgentDecisionConsumer_HandleEnvelope(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)

	// HandleEnvelope now takes the proto BINARY bytes directly (the
	// in-process bus + integration tests carry the same wire bytes the
	// broker delivers).
	if err := sub.HandleEnvelope(context.Background(), newPayload(t, "accepted")); err != nil {
		t.Fatalf("handle envelope: %v", err)
	}
	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1 projection via envelope path; got %d", len(rec))
	}
	if rec[0].DecisionType != "qgen.quality_gate.accepted" {
		t.Fatalf("DecisionType via envelope = %q", rec[0].DecisionType)
	}
	if rec[0].TenantID != adlTestTenantID {
		t.Fatalf("TenantID via envelope = %q", rec[0].TenantID)
	}
}

// _ uses projector import — ensures Go won't drop it as unused even if
// future refactor removes direct test references.
var _ projector.IncomingEvent
