// BiasTestConsumer eventbus binding helpers — the D4 (fairness)
// half of the O+ golden evidence pipeline (ADR-173, CHO-1641).
//
// Bridges the eventbus delivery to the typed BiasTestConsumer.Handle
// (body + BiasTestAttrs).
//
// The durable consumer name: the canonical "{subscriber-svc}.{topic-suffix}"
// form — production binds to `chora-governance.bias-test-completed`.
//
// Redelivery: the eventbus acks on nil and nacks on error; persistent
// failures hit the _dlq.<subject> dead-letter stream after MaxDeliver
// attempts.
package events

import (
	"github.com/apollo-chora/chora-common/envelope"
)

// BiasTestAttrsFromEnvelope lifts the eventbus envelope into the typed
// envelope attrs (fallback only; the proto envelope is authoritative).
func BiasTestAttrsFromEnvelope(env envelope.Envelope) BiasTestAttrs {
	return BiasTestAttrs{
		EventID:        env.EventID,
		IdempotencyKey: env.IdempotencyKey,
		TenantID:       env.TenantID,
	}
}
