// PolicyViolationConsumer eventbus binding helpers: the D3
// (safety_and_robustness) evidence lane for requirement G2.
//
// Bridges the eventbus delivery to the typed PolicyViolationConsumer.Handle
// (body + PolicyViolationAttrs).
//
// Production binds to the provisioned subscription
// `chora-governance.governance-policy-violation_detected`; its dead-letter
// stream routes to _dlq.chora.governance.policy.violation_detected.v1 after 5
// delivery attempts, so a refused message is parked for inspection rather
// than shredded.
package events

import (
	"github.com/apollo-chora/chora-common/envelope"
)

// PolicyViolationAttrsFromEnvelope lifts the eventbus envelope into the
// typed envelope attrs (fallback only; the proto envelope is authoritative).
func PolicyViolationAttrsFromEnvelope(env envelope.Envelope) PolicyViolationAttrs {
	return PolicyViolationAttrs{
		EventID:        env.EventID,
		IdempotencyKey: env.IdempotencyKey,
		TenantID:       env.TenantID,
	}
}
