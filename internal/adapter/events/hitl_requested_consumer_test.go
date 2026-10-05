// Tests for the HITLRequestedConsumer — the chora-governance INBOUND adapter
// that receives `chora.governance.hitl.requested.v1` (the qgen HITL-escalation
// gate event, commit a977a483) and projects it as a PENDING D4
// (fairness_and_human_oversight) hitl_decision_log row.
//
// Wire shape: UNLIKE the AgentDecisionConsumer (BINARY protobuf), this topic is
// NOT yet Schema-Registry-bound — the emitter sends a self-describing JSON body
// matching projector.IncomingEvent's snake_case json tags. The body carries the
// imda_dimension + event_type + the D4 routing fields; routing attrs mirror the
// envelope. The consumer json.Unmarshals the body → IncomingEvent → Project().
package events_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	"github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

const (
	hitlTestTenantID = "01970000-0000-7000-8000-0000000000aa"
	hitlTestGCID     = "01970000-0000-7000-8000-0000000000bb"
	hitlTestDecision = "01970000-0000-7000-8000-0000000000cc"
	hitlTestEventID  = "01970000-0000-7000-8000-0000000000dd"
	hitlTestRunID    = "run-qgen-1"
	hitlTestTrace    = "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"
)

// hitlRequestedBody builds the canonical JSON body the qgen
// HITLDecisionOutboxWriter emits (mirrors projector.IncomingEvent snake_case
// tags + the extra summary/reason/created_at fields).
func hitlRequestedBody() map[string]any {
	return map[string]any{
		"event_id":        hitlTestEventID,
		"tenant_id":       hitlTestTenantID,
		"gcid":            hitlTestGCID,
		"traceparent":     hitlTestTrace,
		"imda_dimension":  "fairness_and_human_oversight",
		"event_type":      "governance.hitl.requested",
		"lifecycle_stage": "runtime",
		"decision_id":     hitlTestDecision,
		"run_id":          hitlTestRunID,
		"agent_id":        "qgen_crew",
		"operator_gcid":   "",
		"hitl_verdict":    "pending",
		"autonomy_level":  "hitl_l0",
		"summary":         "qgen exhausted retries with a quality warning",
		"reason":          "qgen exhausted retries with a quality warning",
		"crew_name":       "mcq_ai_assist",
		"created_at":      "2026-06-02T04:49:10Z",
	}
}

func hitlRequestedJSON(t *testing.T, mut func(m map[string]any)) []byte {
	t.Helper()
	body := hitlRequestedBody()
	if mut != nil {
		mut(body)
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal hitl body: %v", err)
	}
	return b
}

// hitlAttrs mirrors the envelope attributes the dispatcher copies onto the
// event bus message (the emitter mirrors the envelope dict).
func hitlAttrs() map[string]string {
	return map[string]string{
		"event_id":             hitlTestEventID,
		"idempotency_key":      "hitl." + hitlTestTenantID + "." + hitlTestDecision,
		"tenant_id":            hitlTestTenantID,
		"gcid":                 hitlTestGCID,
		"traceparent":          hitlTestTrace,
		"chora_imda_dimension": "fairness_and_human_oversight",
		"event_type":           "governance.hitl.requested",
		"decision_id":          hitlTestDecision,
	}
}

// hitlEnvelope mirrors hitlAttrs as an eventbus envelope for handler tests.
func hitlEnvelope() envelope.Envelope {
	return envelope.Envelope{
		EventID:            hitlTestEventID,
		IdempotencyKey:     "hitl." + hitlTestTenantID + "." + hitlTestDecision,
		TenantID:           hitlTestTenantID,
		GCID:               hitlTestGCID,
		Traceparent:        hitlTestTrace,
		ChoraImdaDimension: "fairness_and_human_oversight",
	}
}

func TestHITLRequestedConsumer_HappyPath_ProjectsPending(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewHITLRequestedConsumer(proj, nil)

	if err := sub.Handle(context.Background(), hitlRequestedJSON(t, nil), hitlAttrs()); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1 projection; got %d", len(rec))
	}
	got := rec[0]
	if got.EventID != hitlTestEventID {
		t.Errorf("EventID = %q; want %q", got.EventID, hitlTestEventID)
	}
	if got.TenantID != hitlTestTenantID {
		t.Errorf("TenantID = %q; want %q", got.TenantID, hitlTestTenantID)
	}
	if got.ImdaDimension != "fairness_and_human_oversight" {
		t.Errorf("ImdaDimension = %q; want fairness_and_human_oversight", got.ImdaDimension)
	}
}

func TestHITLRequestedConsumer_SubscribedTopic(t *testing.T) {
	t.Parallel()
	if events.TopicHITLRequested != "chora.governance.hitl.requested.v1" {
		t.Fatalf("topic constant drifted: %q", events.TopicHITLRequested)
	}
	sub := events.NewHITLRequestedConsumer(events.NewInMemoryProjector(), nil)
	if got := sub.SubscribedTopic(); got != events.TopicHITLRequested {
		t.Fatalf("SubscribedTopic = %q; want %q", got, events.TopicHITLRequested)
	}
}

// TestHITLRequestedConsumer_DimensionRouted asserts the projector receives the
// D4 dimension so it routes to routeD4 → AppendHITLDecision (pending). The
// in-memory projector here only records the IncomingEvent; the pending-persist
// itself is covered by the projector + repo tests.
func TestHITLRequestedConsumer_RoutesViaRealProjectorToPending(t *testing.T) {
	t.Parallel()
	// Use the REAL projector over an in-memory evidence repo to prove the full
	// decode → Project → pending-persist path lands a pending hitl row.
	repo := evidence.NewInMemoryRepository()
	realProj := projector.New(repo)
	sub := events.NewHITLRequestedConsumer(realProj, nil)

	if err := sub.Handle(context.Background(), hitlRequestedJSON(t, nil), hitlAttrs()); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rows, err := repo.QueryHITLDecisions(context.Background(), evidence.QueryFilter{TenantID: hitlTestTenantID})
	if err != nil {
		t.Fatalf("QueryHITLDecisions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 pending hitl row; got %d", len(rows))
	}
	if string(rows[0].Decision) != "pending" {
		t.Errorf("Decision = %q; want pending", rows[0].Decision)
	}
	if rows[0].OperatorGcid != "" {
		t.Errorf("OperatorGcid = %q; want empty on a pending gate", rows[0].OperatorGcid)
	}
	if rows[0].Note != "qgen exhausted retries with a quality warning" {
		t.Errorf("Note = %q; want the summary", rows[0].Note)
	}
}

func TestHITLRequestedConsumer_FallsBackToAttrsForEnvelope(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewHITLRequestedConsumer(proj, nil)

	// Body omits envelope-mandatory fields; the consumer falls back to attrs.
	body := hitlRequestedJSON(t, func(m map[string]any) {
		delete(m, "event_id")
		delete(m, "tenant_id")
		delete(m, "imda_dimension")
	})
	if err := sub.Handle(context.Background(), body, hitlAttrs()); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("expected 1 projection; got %d", len(rec))
	}
	if rec[0].EventID != hitlTestEventID {
		t.Errorf("EventID fallback = %q; want %q", rec[0].EventID, hitlTestEventID)
	}
	if rec[0].TenantID != hitlTestTenantID {
		t.Errorf("TenantID fallback = %q; want %q", rec[0].TenantID, hitlTestTenantID)
	}
	if rec[0].ImdaDimension != "fairness_and_human_oversight" {
		t.Errorf("ImdaDimension fallback = %q; want fairness_and_human_oversight", rec[0].ImdaDimension)
	}
}

func TestHITLRequestedConsumer_RejectsMissingEventID(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewHITLRequestedConsumer(proj, nil)
	body := hitlRequestedJSON(t, func(m map[string]any) { delete(m, "event_id") })
	attrs := hitlAttrs()
	delete(attrs, "event_id")
	err := sub.Handle(context.Background(), body, attrs)
	if err == nil || !strings.Contains(err.Error(), "event_id") {
		t.Fatalf("expected event_id required error; got %v", err)
	}
	if len(proj.Recorded()) != 0 {
		t.Fatalf("must not project on validation failure")
	}
}

func TestHITLRequestedConsumer_RejectsMissingTenantID(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewHITLRequestedConsumer(proj, nil)
	body := hitlRequestedJSON(t, func(m map[string]any) { delete(m, "tenant_id") })
	attrs := hitlAttrs()
	delete(attrs, "tenant_id")
	err := sub.Handle(context.Background(), body, attrs)
	if err == nil || !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("expected tenant_id required error; got %v", err)
	}
}

// TestHITLRequestedConsumer_RejectsWrongDimension — this consumer is the D4
// (fairness_and_human_oversight) receiver; a body carrying a different
// dimension is a routing error → NACK → DLQ (fail loud).
func TestHITLRequestedConsumer_RejectsWrongDimension(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewHITLRequestedConsumer(proj, nil)
	body := hitlRequestedJSON(t, func(m map[string]any) { m["imda_dimension"] = "accountability" })
	attrs := hitlAttrs()
	attrs["chora_imda_dimension"] = "accountability"
	err := sub.Handle(context.Background(), body, attrs)
	if err == nil || !strings.Contains(err.Error(), "imda_dimension") {
		t.Fatalf("expected imda_dimension validation error; got %v", err)
	}
}

// TestHITLRequestedConsumer_RejectsMalformedJSON asserts the fail-loud DLQ path:
// non-JSON bytes → error → NACK.
func TestHITLRequestedConsumer_RejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewHITLRequestedConsumer(proj, nil)
	err := sub.Handle(context.Background(), []byte("{not-json"), hitlAttrs())
	if err == nil {
		t.Fatalf("expected JSON decode error; got nil")
	}
	if len(proj.Recorded()) != 0 {
		t.Fatalf("malformed JSON must not project")
	}
}

func TestHITLRequestedConsumer_Dedupes(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	sub := events.NewHITLRequestedConsumer(proj, nil)
	body := hitlRequestedJSON(t, nil)
	attrs := hitlAttrs()
	if err := sub.Handle(context.Background(), body, attrs); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	if err := sub.Handle(context.Background(), body, attrs); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if got := len(proj.Recorded()); got != 1 {
		t.Fatalf("expected 1 projection (idempotent); got %d", got)
	}
}

func TestHITLRequestedConsumer_PropagatesProjectorError(t *testing.T) {
	t.Parallel()
	proj := events.NewInMemoryProjector()
	proj.SetFailNext(true, errors.New("repo down"))
	sub := events.NewHITLRequestedConsumer(proj, nil)
	err := sub.Handle(context.Background(), hitlRequestedJSON(t, nil), hitlAttrs())
	if err == nil || !strings.Contains(err.Error(), "repo down") {
		t.Fatalf("expected projector error to propagate; got %v", err)
	}
}

func TestHITLRequestedConsumer_NilSubscriber(t *testing.T) {
	t.Parallel()
	var sub *events.HITLRequestedConsumer
	err := sub.Handle(context.Background(), hitlRequestedJSON(t, nil), hitlAttrs())
	if err == nil || !strings.Contains(err.Error(), "not initialised") {
		t.Fatalf("expected not-initialised error; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// eventbus binding helpers — error contract (D6 Pillar 2 delivery resilience)
// -----------------------------------------------------------------------------

// TestHITLRequestedHandler_Success — happy path returns nil (commits the
// pending row), never errors.
func TestHITLRequestedHandler_Success(t *testing.T) {
	t.Parallel()
	sub := events.NewHITLRequestedConsumer(events.NewInMemoryProjector(), nil)
	handler := events.HITLRequestedHandler(sub)
	msg := eventbus.Message{
		Payload:  hitlRequestedJSON(t, nil),
		Envelope: hitlEnvelope(),
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("HITLRequestedHandler: %v", err)
	}
}

// TestHITLRequestedHandler_ErrorContract — a malformed body errors so the
// bus redelivers + (after max attempts) dead-letters. Losing the pending
// row would leave the O+ queue silently empty (the load-bearing failure mode).
func TestHITLRequestedHandler_ErrorContract(t *testing.T) {
	t.Parallel()
	sub := events.NewHITLRequestedConsumer(events.NewInMemoryProjector(), nil)
	handler := events.HITLRequestedHandler(sub)
	if err := handler(context.Background(), eventbus.Message{Payload: []byte("{not-json")}); err == nil {
		t.Fatal("expected error on malformed body")
	}
	if err := (events.HITLRequestedHandler(nil))(context.Background(), eventbus.Message{}); err == nil {
		t.Fatal("expected error for nil consumer")
	}
}
