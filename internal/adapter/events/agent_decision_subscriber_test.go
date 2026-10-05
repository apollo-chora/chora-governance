// Tests for the AgentDecisionConsumer's eventbus binding helpers —
// RED→GREEN for the production wiring that chora-governance
// `cmd/server/main.go` exercises (Gate #8 of OE-AI-ASSIST).
//
// The helpers convert an `eventbus.Message` (envelope + raw payload) into
// the (body, AgentDecisionEnvelopeAttrs) shape Handle() expects.
package events_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	"github.com/apollo-chora/chora-governance/internal/adapter/events"
)

// TestEnvelopeAttrsFromEnvelope_AllFields verifies the envelope conversion
// path the eventbus subscriber takes.
func TestEnvelopeAttrsFromEnvelope_AllFields(t *testing.T) {
	t.Parallel()

	attrs := events.EnvelopeAttrsFromEnvelope(envelope.Envelope{
		EventID:            adlTestEventID,
		IdempotencyKey:     adlTestIdempotency,
		TenantID:           adlTestTenantID,
		GCID:               adlTestGCID,
		Traceparent:        adlTestTrace,
		Tracestate:         adlTestTracestate,
		ChoraImdaDimension: "accountability",
		SchemaVersion:      1,
	})

	if attrs.EventID != adlTestEventID {
		t.Errorf("EventID = %q; want %q", attrs.EventID, adlTestEventID)
	}
	if attrs.IdempotencyKey != adlTestIdempotency {
		t.Errorf("IdempotencyKey = %q; want %q", attrs.IdempotencyKey, adlTestIdempotency)
	}
	if attrs.TenantID != adlTestTenantID {
		t.Errorf("TenantID = %q; want %q", attrs.TenantID, adlTestTenantID)
	}
	if attrs.GCID != adlTestGCID {
		t.Errorf("GCID = %q; want %q", attrs.GCID, adlTestGCID)
	}
	if attrs.Traceparent != adlTestTrace {
		t.Errorf("Traceparent = %q; want %q", attrs.Traceparent, adlTestTrace)
	}
	if attrs.Tracestate != adlTestTracestate {
		t.Errorf("Tracestate = %q; want %q", attrs.Tracestate, adlTestTracestate)
	}
	if attrs.ChoraImdaDimension != "accountability" {
		t.Errorf("ChoraImdaDimension = %q; want %q", attrs.ChoraImdaDimension, "accountability")
	}
	if attrs.SchemaVersion != "1" {
		t.Errorf("SchemaVersion = %q; want %q", attrs.SchemaVersion, "1")
	}
}

// TestEnvelopeAttrsFromEnvelope_MissingFieldsSafe — zero-value envelope
// yields zero-value attrs. The consumer's validateAgentDecision will reject
// empty mandatory fields downstream; this helper just lifts the envelope
// verbatim.
func TestEnvelopeAttrsFromEnvelope_MissingFieldsSafe(t *testing.T) {
	t.Parallel()

	attrs := events.EnvelopeAttrsFromEnvelope(envelope.Envelope{})
	if attrs.EventID != "" {
		t.Errorf("EventID = %q; want empty", attrs.EventID)
	}
	if attrs.TenantID != "" {
		t.Errorf("TenantID = %q; want empty", attrs.TenantID)
	}

	attrs2 := events.EnvelopeAttrsFromEnvelope(envelope.Envelope{EventID: "only-event-id"})
	if attrs2.EventID != "only-event-id" {
		t.Errorf("EventID = %q; want %q", attrs2.EventID, "only-event-id")
	}
	if attrs2.TenantID != "" {
		t.Errorf("TenantID = %q; want empty", attrs2.TenantID)
	}
}

// TestAgentDecisionHandler_Success wires the consumer through the eventbus
// handler. Happy path → nil error.
func TestAgentDecisionHandler_Success(t *testing.T) {
	t.Parallel()

	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)
	handler := events.AgentDecisionHandler(sub)

	msg := eventbusMessage(newPayload(t, "accepted"), envelope.Envelope{
		EventID:            adlTestEventID,
		IdempotencyKey:     adlTestIdempotency,
		TenantID:           adlTestTenantID,
		GCID:               adlTestGCID,
		ChoraImdaDimension: "accountability",
	})

	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("AgentDecisionHandler: %v", err)
	}

	rec := proj.Recorded()
	if len(rec) != 1 {
		t.Fatalf("projector recorded = %d; want 1", len(rec))
	}
	if rec[0].DecisionType != "qgen.quality_gate.accepted" {
		t.Errorf("DecisionType = %q; want qgen.quality_gate.accepted", rec[0].DecisionType)
	}
}

// TestAgentDecisionHandler_BadPayloadErrors verifies that a malformed
// payload surfaces as an error so the bus redelivers (and routes to the DLQ
// after MaxDeliver attempts).
func TestAgentDecisionHandler_BadPayloadErrors(t *testing.T) {
	t.Parallel()

	proj := events.NewInMemoryProjector()
	sub := events.NewAgentDecisionConsumer(proj, nil)
	handler := events.AgentDecisionHandler(sub)

	msg := eventbusMessage([]byte("not-proto"), envelope.Envelope{
		EventID:            adlTestEventID,
		TenantID:           adlTestTenantID,
		ChoraImdaDimension: "accountability",
	})

	if err := handler(context.Background(), msg); err == nil {
		t.Fatalf("AgentDecisionHandler: expected error on bad payload")
	}
}

// TestAgentDecisionHandler_ProjectorError verifies that a downstream
// projector error also surfaces as an error. The bus retry + DLQ handles
// persistent failures.
func TestAgentDecisionHandler_ProjectorError(t *testing.T) {
	t.Parallel()

	proj := events.NewInMemoryProjector()
	proj.SetFailNext(true, errors.New("projector down"))
	sub := events.NewAgentDecisionConsumer(proj, nil)
	handler := events.AgentDecisionHandler(sub)

	msg := eventbusMessage(newPayload(t, "accepted"), envelope.Envelope{
		EventID:            adlTestEventID,
		IdempotencyKey:     adlTestIdempotency,
		TenantID:           adlTestTenantID,
		GCID:               adlTestGCID,
		ChoraImdaDimension: "accountability",
	})

	if err := handler(context.Background(), msg); err == nil {
		t.Fatalf("AgentDecisionHandler: expected error on projector failure")
	}
}

// TestAgentDecisionHandler_NilConsumerSafe — defensive: a nil consumer
// surfaces a clean error rather than panicking.
func TestAgentDecisionHandler_NilConsumerSafe(t *testing.T) {
	t.Parallel()

	handler := events.AgentDecisionHandler(nil)
	if err := handler(context.Background(), eventbus.Message{}); err == nil {
		t.Fatalf("AgentDecisionHandler: expected error on nil consumer")
	}
}

// eventbusMessage builds an eventbus.Message with the given payload +
// envelope for handler tests.
func eventbusMessage(payload []byte, env envelope.Envelope) eventbus.Message {
	return eventbus.Message{
		Subject:  events.TopicAgentDecisionLogged,
		Envelope: env,
		Payload:  payload,
	}
}
