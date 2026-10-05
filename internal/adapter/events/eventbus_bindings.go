// eventbus_bindings.go — adapters that project eventbus deliveries onto the
// governance subscriber methods. Kept separate from the subscribers so the
// domain-facing Handle* methods stay transport-agnostic.
//
// Each handler takes the eventbus.Message BY VALUE; returning an error nacks
// the delivery so the bus redelivers (DLQ after MaxDeliver attempts).
package events

import (
	"context"
	"errors"

	"github.com/apollo-chora/chora-common/eventbus"
)

// AgentDecisionHandler adapts the AgentDecisionConsumer to an
// eventbus.Handler. The producer publishes BINARY-protobuf
// AgentDecisionLogged bytes; the consumer proto.Unmarshals the payload and
// prefers the proto envelope, falling back to the eventbus envelope attrs.
func AgentDecisionHandler(consumer *AgentDecisionConsumer) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if consumer == nil {
			return errors.New("events: AgentDecisionConsumer is nil; cannot dispatch")
		}
		return consumer.Handle(ctx, msg.Payload, EnvelopeAttrsFromEnvelope(msg.Envelope))
	}
}

// AiAssistCompletedHandler adapts the AiAssistCompletedConsumer to an
// eventbus.Handler.
func AiAssistCompletedHandler(consumer *AiAssistCompletedConsumer) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if consumer == nil {
			return errors.New("events: AiAssistCompletedConsumer is nil; cannot dispatch")
		}
		return consumer.Handle(ctx, msg.Payload, AiAssistCompletedAttrsFromEnvelope(msg.Envelope))
	}
}

// WeaknessAnalyzedHandler adapts the WeaknessAnalyzedConsumer to an
// eventbus.Handler.
func WeaknessAnalyzedHandler(consumer *WeaknessAnalyzedConsumer) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if consumer == nil {
			return errors.New("events: WeaknessAnalyzedConsumer is nil; cannot dispatch")
		}
		return consumer.Handle(ctx, msg.Payload, WeaknessAnalyzedAttrsFromEnvelope(msg.Envelope))
	}
}

// BiasTestHandler adapts the BiasTestConsumer to an eventbus.Handler.
func BiasTestHandler(consumer *BiasTestConsumer) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if consumer == nil {
			return errors.New("events: BiasTestConsumer is nil; cannot dispatch")
		}
		return consumer.Handle(ctx, msg.Payload, BiasTestAttrsFromEnvelope(msg.Envelope))
	}
}

// PolicyViolationHandler adapts the PolicyViolationConsumer to an
// eventbus.Handler.
func PolicyViolationHandler(consumer *PolicyViolationConsumer) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if consumer == nil {
			return errors.New("events: PolicyViolationConsumer is nil; cannot dispatch")
		}
		return consumer.Handle(ctx, msg.Payload, PolicyViolationAttrsFromEnvelope(msg.Envelope))
	}
}

// HITLRequestedHandler adapts the HITLRequestedConsumer to an
// eventbus.Handler. The consumer reads the raw attribute map, so the
// eventbus envelope is projected onto the map shape it expects.
func HITLRequestedHandler(consumer *HITLRequestedConsumer) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if consumer == nil {
			return errors.New("events: HITLRequestedConsumer is nil; cannot dispatch")
		}
		return consumer.Handle(ctx, msg.Payload, hitlAttrsFromEnvelope(msg.Envelope))
	}
}

// AuditPaymentsHandler adapts the AuditPaymentsSubscriber to an
// eventbus.Handler. The subscriber routes by subject, so the handler is
// bound per-topic with the subject captured in the closure.
func AuditPaymentsHandler(sub *AuditPaymentsSubscriber, subject string) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		return HandleAuditPaymentsMessage(ctx, sub, subject, msg)
	}
}

// AuditEgressHandler adapts the AuditEgressSubscriber to an eventbus.Handler.
func AuditEgressHandler(sub *AuditEgressSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		return HandleExternalEgressMessage(ctx, sub, msg)
	}
}

// EvidenceRecordedHandler adapts the EvidenceRecordedSubscriber to an
// eventbus.Handler.
func EvidenceRecordedHandler(sub *EvidenceRecordedSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		return HandleEvidenceRecordedMessage(ctx, sub, msg)
	}
}
