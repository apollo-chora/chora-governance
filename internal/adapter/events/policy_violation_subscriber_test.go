package events

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"
)

func TestPolicyViolationAttrsFromEnvelope(t *testing.T) {
	if got := PolicyViolationAttrsFromEnvelope(envelope.Envelope{}); got != (PolicyViolationAttrs{}) {
		t.Errorf("zero envelope = %+v, want zero", got)
	}
	got := PolicyViolationAttrsFromEnvelope(envelope.Envelope{
		EventID:        "e1",
		IdempotencyKey: "k1",
		TenantID:       "t1",
	})
	if got.EventID != "e1" || got.IdempotencyKey != "k1" || got.TenantID != "t1" {
		t.Errorf("attrs = %+v", got)
	}
}

// A decoded, projected message must succeed. An undecodable one must error
// so the bus redelivers it and the DLQ eventually catches it.
func TestPolicyViolationHandler_ErrorContract(t *testing.T) {
	consumer := NewPolicyViolationConsumer(&capturingProjector{}, nil)
	handler := PolicyViolationHandler(consumer)

	if err := handler(context.Background(), eventbus.Message{Payload: violationBody(t, nil)}); err != nil {
		t.Fatalf("PolicyViolationHandler: %v", err)
	}

	if err := handler(context.Background(), eventbus.Message{Payload: []byte("\xff\xfenot-a-proto")}); err == nil {
		t.Error("undecodable message should error")
	}

	if err := (PolicyViolationHandler(nil))(context.Background(), eventbus.Message{}); err == nil {
		t.Error("nil consumer should error")
	}
}

// The eventbus envelope must actually reach the consumer as the envelope
// fallback: a body whose envelope lost its ids still projects, using the
// envelope's attribute projection.
func TestPolicyViolationHandler_PassesAttrs(t *testing.T) {
	proj := &capturingProjector{}
	consumer := NewPolicyViolationConsumer(proj, nil)

	body := violationBody(t, func(m *governancev1.PolicyViolationDetected) {
		m.Envelope.EventId = ""
		m.Envelope.TenantId = ""
		m.Envelope.IdempotencyKey = ""
	})
	err := (PolicyViolationHandler(consumer))(context.Background(), eventbus.Message{
		Payload: body,
		Envelope: envelope.Envelope{
			EventID:        "attr-e1",
			IdempotencyKey: "attr-k1",
			TenantID:       "44444444-4444-7444-8444-000000000004",
		},
	})
	if err != nil {
		t.Fatalf("PolicyViolationHandler: %v", err)
	}
	all := proj.all()
	if len(all) != 1 {
		t.Fatalf("rows = %d, want 1", len(all))
	}
	if all[0].EventID != "attr-e1" || all[0].TenantID != "44444444-4444-7444-8444-000000000004" {
		t.Errorf("envelope was not lifted into the consumer: %q / %q", all[0].EventID, all[0].TenantID)
	}
}

// HandleEnvelope is the in-process convenience path.
func TestPolicyViolation_HandleEnvelope(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)
	if err := c.HandleEnvelope(context.Background(), violationBody(t, nil)); err != nil {
		t.Fatalf("HandleEnvelope: %v", err)
	}
	if got := len(proj.all()); got != 1 {
		t.Fatalf("rows = %d, want 1", got)
	}
}

// An empty description is not a decode failure: the violation is still real.
func TestPolicyViolation_EmptyDescriptionStaysEvidence(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)
	body := violationBody(t, func(m *governancev1.PolicyViolationDetected) { m.Description = "" })
	if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	all := proj.all()
	if len(all) != 1 || all[0].AgentID != AgentIDUnattributed {
		t.Fatalf("rows=%d agent=%q, want 1 unattributed row", len(all), all[0].AgentID)
	}
}
