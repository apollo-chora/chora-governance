// HITLRequestedConsumer eventbus binding helpers.
//
// Bridges the eventbus delivery to the typed HITLRequestedConsumer.Handle
// (body []byte + raw attribute map) signature.
//
// Unlike the AgentDecision binding (which lifts the envelope into a typed
// AgentDecisionEnvelopeAttrs), the HITL consumer takes the raw attribute map
// directly — the body is self-describing JSON (projector.IncomingEvent), so
// the consumer reads only the few envelope-mandatory attrs it needs as a
// fallback.
//
// Redelivery: the eventbus acks on nil and nacks on error; persistent
// failures hit the _dlq.<subject> dead-letter stream after MaxDeliver
// attempts.
package events

import (
	"strconv"

	"github.com/apollo-chora/chora-common/envelope"
)

// hitlAttrsFromEnvelope projects the eventbus envelope onto the raw
// attribute map the HITLRequestedConsumer.Handle path expects.
func hitlAttrsFromEnvelope(env envelope.Envelope) map[string]string {
	return map[string]string{
		"event_id":        env.EventID,
		"idempotency_key": env.IdempotencyKey,
		"tenant_id":       env.TenantID,
		"gcid":            env.GCID,
		"traceparent":     env.Traceparent,
		"tracestate":      env.Tracestate,
		"schema_version":  strconv.FormatInt(int64(env.SchemaVersion), 10),
	}
}
