// AgentDecisionConsumer eventbus binding helpers.
//
// Bridges the eventbus delivery (envelope + raw payload) to the typed
// AgentDecisionConsumer.Handle (body []byte + AgentDecisionEnvelopeAttrs)
// signature.
//
// Per Tier 2 D8 + Tier 3 D11: this is the chora-governance INBOUND
// adapter for Gate #8 AgentDecisionLog events. The durable consumer name
// (per chora-infra naming): the canonical "{subscriber-svc}.{topic-suffix}"
// form — production binds to `chora-governance.agent-decision-logged`.
//
// Redelivery: the eventbus acks on nil and nacks on error; persistent
// failures hit the _dlq.<subject> dead-letter stream after MaxDeliver
// attempts.
package events

import (
	"strconv"

	"github.com/apollo-chora/chora-common/envelope"
)

// EnvelopeAttrsFromEnvelope converts the eventbus envelope into the typed
// AgentDecisionEnvelopeAttrs the consumer Handle path expects.
//
// Missing fields yield zero values; the consumer's validateAgentDecision
// guard rejects empty mandatory fields downstream so a broken envelope
// surfaces as a clear validation error rather than a silent dimension
// mismatch.
//
// Exported (capitalized) so the unit tests can exercise the conversion in
// isolation.
func EnvelopeAttrsFromEnvelope(env envelope.Envelope) AgentDecisionEnvelopeAttrs {
	return AgentDecisionEnvelopeAttrs{
		EventID:            env.EventID,
		IdempotencyKey:     env.IdempotencyKey,
		TenantID:           env.TenantID,
		GCID:               env.GCID,
		Traceparent:        env.Traceparent,
		Tracestate:         env.Tracestate,
		ChoraImdaDimension: env.ChoraImdaDimension,
		SchemaVersion:      strconv.FormatInt(int64(env.SchemaVersion), 10),
	}
}
