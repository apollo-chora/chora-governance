// WeaknessAnalyzedConsumer eventbus binding helpers — the D2
// (transparency) governance projection of the ADR-205 Growth-Edge analyser
// graduation (epic CHO-1952, story CHO-1955 / WS-3).
//
// Bridges the eventbus delivery to the typed WeaknessAnalyzedConsumer.Handle
// (body + WeaknessAnalyzedAttrs).
//
// The durable consumer name: the canonical "{subscriber-svc}.{topic-suffix}"
// form — production binds to `chora-governance.consumption-weakness-analyzed`.
//
// Redelivery: the eventbus acks on nil and nacks on error; persistent
// failures hit the _dlq.<subject> dead-letter stream after MaxDeliver
// attempts.
package events

import (
	"github.com/apollo-chora/chora-common/envelope"
)

// WeaknessAnalyzedAttrsFromEnvelope lifts the eventbus envelope into the
// typed envelope attrs the consumer Handle path expects. Missing fields
// yield zero values; the proto envelope (field 1) is authoritative and
// supplies the mandatory fields, so the attrs are a fallback only.
func WeaknessAnalyzedAttrsFromEnvelope(env envelope.Envelope) WeaknessAnalyzedAttrs {
	return WeaknessAnalyzedAttrs{
		EventID:        env.EventID,
		IdempotencyKey: env.IdempotencyKey,
		TenantID:       env.TenantID,
		GCID:           env.GCID,
		Traceparent:    env.Traceparent,
	}
}
