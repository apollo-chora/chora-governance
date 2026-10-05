// AiAssistCompletedConsumer eventbus binding helpers — the D2
// (transparency) half of the O+ golden evidence pipeline (ADR-173, CHO-1641).
//
// Bridges the eventbus delivery to the typed AiAssistCompletedConsumer.Handle
// (body + AiAssistCompletedAttrs).
//
// The durable consumer name: the canonical "{subscriber-svc}.{topic-suffix}"
// form — production binds to `chora-governance.creation-ai-assist-completed`.
//
// Redelivery: the eventbus acks on nil and nacks on error; persistent
// failures hit the _dlq.<subject> dead-letter stream after MaxDeliver
// attempts.
package events

import (
	"github.com/apollo-chora/chora-common/envelope"
)

// AiAssistCompletedAttrsFromEnvelope lifts the eventbus envelope into the
// typed envelope attrs the consumer Handle path expects. Missing fields
// yield zero values; the proto envelope (field 1) is authoritative and
// supplies the mandatory fields, so the attrs are a fallback only.
func AiAssistCompletedAttrsFromEnvelope(env envelope.Envelope) AiAssistCompletedAttrs {
	return AiAssistCompletedAttrs{
		EventID:        env.EventID,
		IdempotencyKey: env.IdempotencyKey,
		TenantID:       env.TenantID,
		GCID:           env.GCID,
		Traceparent:    env.Traceparent,
	}
}
