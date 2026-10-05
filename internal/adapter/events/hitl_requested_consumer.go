// HITLRequestedConsumer routes `chora.governance.hitl.requested.v1` events to
// the chora-governance Projector, which enqueues a PENDING D4
// (fairness_and_human_oversight) hitl_decision_log row that the O+ Human-
// Oversight queue (/api/hitl/pending) surfaces.
//
// This closes the receive side of the O+ HITL "Human Oversight" pipeline: the
// chora-ai-kernel-orchestrator qgen crew EMITS this event (commit a977a483)
// when a quality gate exhausts retries with a warning, but governance had no
// subscriber routing it to the projector — the only governance consumer
// reaching the projector (AgentDecisionConsumer) hardcodes
// imda_dimension=accountability and would NACK a D4 event.
//
// Source-of-truth:
//   - services/chora-ai-kernel-orchestrator/.../pubsub/hitl_decision_outbox_writer.py
//     (the emitter — body shape + topic + attributes)
//   - internal/domain/projector/projector.go §routeD4 (the HITL branch →
//     NewPendingHITLDecision → AppendHITLDecision)
//   - .claude/skills/imda-governance-4-dimensions/SKILL.md (D4 HITL routing)
//   - [[adr141-imda-dimension-labels-reconciliation]] (canonical
//     "fairness_and_human_oversight" label)
//
// Wire shape: UNLIKE the AgentDecisionConsumer (BINARY protobuf,
// Schema-Registry-bound), this topic is NOT yet Schema-Registry-bound (the
// future ADR-167-style migration will move it to BINARY). The emitter sends a
// self-describing JSON body whose snake_case keys mirror
// projector.IncomingEvent's json tags. The envelope-mandatory fields are also
// mirrored onto the Pub/Sub message attributes (the emitter copies the
// envelope dict), so this consumer prefers the body's value and falls back to
// the routing attrs when a field is absent on the body.
//
// Cross-DB queries forbidden — chora-governance reads only its own DB.
// Hexagonal: this is an INBOUND adapter; depends only on the projector port.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// TopicHITLRequested is the canonical governance-domain topic for the qgen
// HITL gate-requested event. Governance-domain topic (chora.governance.*)
// because the gate persists into the governance hitl_decision_log. Provisioned
// by chora-infra (parallel track) — see chora-infra/topics.yaml.
const TopicHITLRequested = "chora.governance.hitl.requested.v1"

// HITLRequestedInboxTTL is the dedupe-key retention window. Mirrors the
// AgentDecision consumer (24h covers the Pub/Sub redelivery window reduced for
// typical orchestrator → governance latency).
const HITLRequestedInboxTTL = 24 * time.Hour

// expectedHITLDimension is the IMDA dimension this subscriber accepts. HITL
// escalations are D4 (fairness_and_human_oversight) evidence per ADR-141.
const expectedHITLDimension = "fairness_and_human_oversight"

// HITLRequestedConsumer ingests HITL gate-requested events + routes them
// through the chora-governance projector as a PENDING D4 gate.
type HITLRequestedConsumer struct {
	proj  ProjectorPort
	inbox idempotent.Store
	ttl   time.Duration

	mu sync.Mutex
}

// NewHITLRequestedConsumer wires the projector + an idempotency inbox. When
// inbox is nil, an in-memory store is allocated. The ProjectorPort is the same
// minimal port the AgentDecisionConsumer uses.
func NewHITLRequestedConsumer(proj ProjectorPort, inbox idempotent.Store) *HITLRequestedConsumer {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &HITLRequestedConsumer{
		proj:  proj,
		inbox: inbox,
		ttl:   HITLRequestedInboxTTL,
	}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (c *HITLRequestedConsumer) SubscribedTopic() string {
	return TopicHITLRequested
}

// Handle processes one decoded message.
//
// `body` is the Pub/Sub message data (JSON matching projector.IncomingEvent);
// `attrs` is the raw Pub/Sub message attributes (the mirrored envelope). The
// consumer prefers body values for the envelope-mandatory fields and falls
// back to attrs when a field is blank on the body.
//
// Idempotency: the idempotency_key (from attrs, deterministic per
// (tenant_id, decision_id)) is the dedupe key, falling back to event_id. The
// projector is ALSO idempotent on EventID at the repo layer.
//
// Returns nil on successful append. Returns an error on JSON decode failure,
// validation failure, or downstream projector error — the caller (a Pub/Sub
// subscriber adapter) NACKs on error so Pub/Sub redelivers / dead-letters.
func (c *HITLRequestedConsumer) Handle(
	ctx context.Context,
	body []byte,
	attrs map[string]string,
) error {
	if c == nil || c.proj == nil {
		return errors.New("events: HITLRequestedConsumer not initialised")
	}

	// FAIL LOUD: a malformed body returns an error so the message NACKs → DLQ.
	// NO silent drop.
	var ev projector.IncomingEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return fmt.Errorf("events: hitl_requested json decode: %w", err)
	}

	// Envelope-mandatory fields prefer the body; fall back to routing attrs.
	if attrs != nil {
		ev.EventID = firstNonBlank(ev.EventID, attrs["event_id"])
		ev.TenantID = firstNonBlank(ev.TenantID, attrs["tenant_id"])
		ev.ImdaDimension = firstNonBlank(ev.ImdaDimension, attrs["chora_imda_dimension"])
		ev.EventType = firstNonBlank(ev.EventType, attrs["event_type"])
		ev.Traceparent = firstNonBlank(ev.Traceparent, attrs["traceparent"])
	}

	if err := validateHITLRequested(ev); err != nil {
		return err
	}

	// Dedupe key: prefer the envelope idempotency_key (deterministic per
	// (tenant_id, decision_id)), fall back to event_id.
	dedupeKey := ""
	if attrs != nil {
		dedupeKey = strings.TrimSpace(attrs["idempotency_key"])
	}
	if dedupeKey == "" {
		dedupeKey = ev.EventID
	}

	return c.inbox.Process(ctx, dedupeKey, c.ttl, func() error {
		return c.proj.Project(ctx, ev)
	})
}

// HandleEnvelope is a convenience wrapper for the in-process bus + integration
// tests: the in-process path carries the same JSON body the broker delivers
// with empty routing attrs (the body is self-describing).
func (c *HITLRequestedConsumer) HandleEnvelope(ctx context.Context, raw []byte) error {
	return c.Handle(ctx, raw, nil)
}

// validateHITLRequested enforces the envelope-mandatory fields + the D4
// dimension guard. Dimension canonicalisation (v1 alias → canonical) is the
// projector's responsibility; here we accept the canonical D4 label or its v1
// alias (operations_management) so a mis-emitted v1 label still routes.
func validateHITLRequested(ev projector.IncomingEvent) error {
	if strings.TrimSpace(ev.EventID) == "" {
		return errors.New("events: hitl_requested envelope event_id required")
	}
	if strings.TrimSpace(ev.TenantID) == "" {
		return errors.New("events: hitl_requested envelope tenant_id required")
	}
	if strings.TrimSpace(ev.DecisionID) == "" {
		return errors.New("events: hitl_requested payload decision_id required")
	}
	dim := canonicaliseHITLDimension(ev.ImdaDimension)
	if dim != expectedHITLDimension {
		return fmt.Errorf(
			"events: hitl_requested unexpected imda_dimension %q (want %q)",
			ev.ImdaDimension, expectedHITLDimension,
		)
	}
	return nil
}

// canonicaliseHITLDimension maps the deprecated v1 D4 alias
// (operations_management) to the canonical fairness_and_human_oversight per
// ADR-141, leaving other values lowercased-as-is.
func canonicaliseHITLDimension(in string) string {
	v := strings.ToLower(strings.TrimSpace(in))
	if v == "operations_management" {
		return expectedHITLDimension
	}
	return v
}
