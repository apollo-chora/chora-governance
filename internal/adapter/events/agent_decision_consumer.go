// AgentDecisionConsumer routes `chora.observability.agent_decision.logged.v1`
// events to the chora-governance Projector for IMDA D1 (accountability)
// evidence aggregation per ADR-141 + Acceptance Gate #8 of OE-AI-ASSIST.
//
// Source-of-truth:
//   - docs/m13/oe-ai-assist-session-close-2026-05-17.md §Step 6 row "Orchestrator
//     emits ... per quality_gate decision"
//   - chora-contracts/proto/events/observability/agent_decision.proto
//     §AgentDecisionLogged (envelope-shaped event)
//   - .claude/skills/imda-governance-4-dimensions/SKILL.md (D1 routing)
//   - [[adr141-imda-dimension-labels-reconciliation]] (canonical
//     "accountability" label)
//
// Wire shape (ADR-167 Phase 2 — JSON→Protobuf migration): the
// chora-ai-kernel-orchestrator publishes via its outbox dispatcher; the
// Pub/Sub message's `data` field is a BINARY-protobuf
// `chora.observability.v1.AgentDecisionLogged` (the topic is
// Schema-Registry-bound with encoding=BINARY). The EventEnvelope at proto
// field 1 is the AUTHORITATIVE envelope; the `attributes` map MAY still
// carry envelope copies for routing, but the proto envelope wins —
// attributes are read only as a fallback when the proto envelope is absent.
//
// This subscriber:
//  1. proto.Unmarshal the body into AgentDecisionLogged. On error, return
//     it (FAIL LOUD per ADR-167) so the message NACKs → DLQ. NO JSON
//     fallback; NO silent drop; Protobuf only.
//  2. Source the envelope-mandatory fields from the proto envelope (falling
//     back to routing attrs only when the proto envelope is nil), and the
//     qgen-domain detail (decision verdict, attempt_count, max_retries,
//     quality_warning) from the proto `attributes` map per the ADR-167
//     canonical mapping.
//  3. Validate envelope-mandatory fields (tenant_id + event_id +
//     chora_imda_dimension == "accountability").
//  4. Builds a projector.IncomingEvent.
//  5. Hands off to projector.Projector.Project — which appends an
//     AccountabilityEvidence row (D1) via the evidence repo.
//
// Cross-DB queries forbidden — chora-governance reads only its own DB.
// Hexagonal: this is an INBOUND adapter; depends only on the projector port.
package events

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	observabilityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/observability/v1"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// TopicAgentDecisionLogged is the canonical provisioned Pub/Sub topic for
// AgentDecisionLog events per chora-infra/terraform/modules/m10-data-plane/
// main.tf:472. Centralised in chora-489812 (platform host).
const TopicAgentDecisionLogged = "chora.observability.agent_decision.logged.v1"

// AgentDecisionInboxTTL is the dedupe-key retention window. 24h covers the
// Pub/Sub default 7d redelivery window reduced for typical end-to-end
// orchestrator → governance latency (target: seconds).
const AgentDecisionInboxTTL = 24 * time.Hour

// expectedDimension is the IMDA dimension this subscriber accepts.
// chora-governance is the D1 (accountability) consumer per ADR-141.
const expectedDimension = "accountability"

// decodedAgentDecision is the projector-relevant view extracted from the
// inbound AgentDecisionLogged proto per the ADR-167 canonical mapping. It
// is built in extractAgentDecision; envelope-mandatory fields prefer the
// proto envelope (field 1) and fall back to the routing attrs only when the
// proto envelope is absent.
//
// qgen-domain detail (decision verdict, attempt_count, max_retries,
// quality_warning) is sourced from the proto `attributes` map (field 21) —
// the GENERIC proto core stays cross-agent; per-agent detail rides the map.
type decodedAgentDecision struct {
	// Envelope-mandatory
	EventID            string
	IdempotencyKey     string
	TenantID           string
	GCID               string
	Traceparent        string
	Tracestate         string
	ChoraImdaDimension string
	SchemaVersion      string

	// Core / mapped fields
	AssistID    string // decision_id (== invocation_id)
	Agid        string // proto field 4 — the REAL per-agent identity (qgen_question / qgen_critic / oe_evaluator / oe_moderator)
	Decision    string // attributes["decision"] — qgen verdict
	CriticNotes string // output_summary
	OccurredAt  string // decided_at → RFC3339Nano

	// qgen-specific detail from the attributes map
	AttemptCount   int
	MaxRetries     int
	QualityWarning bool

	// Extension fields (proto 12-20) — straight through.
	CrewName         string
	CrewID           string
	IsResume         bool
	IsEvalRun        bool
	AdapterVersion   string
	GuardrailOutcome string
	PromptTokens     int64
	CompletionTokens int64
	CachedTokens     int64
}

// AgentDecisionEnvelopeAttrs are the envelope-derived Pub/Sub message
// attributes. The dispatcher copies them off the outbox row's `envelope`
// JSON column onto Pub/Sub message attributes. The subscriber prefers
// attribute values for envelope-mandatory fields (event_id, tenant_id, etc.)
// because attributes are not impacted by payload schema evolution.
//
// CrewName lives on the envelope (in addition to the payload) so D1
// governance subscribers can dedupe + index by crew without decoding
// the payload — same convention as the existing `decision` envelope
// attr (mirror of publish_refused's refusal_reason / model_armor_verdict
// surfacing).
type AgentDecisionEnvelopeAttrs struct {
	EventID            string
	IdempotencyKey     string
	TenantID           string
	GCID               string
	Traceparent        string
	Tracestate         string
	ChoraImdaDimension string
	SchemaVersion      string
	CrewName           string
}

// ProjectorPort is the minimal port this subscriber needs from the
// projector. Decouples the subscriber from concrete *projector.Projector
// for testability per hexagonal.
type ProjectorPort interface {
	Project(ctx context.Context, ev projector.IncomingEvent) error
}

// AgentDecisionConsumer ingests AgentDecisionLog events + routes them
// through the chora-governance projector for D1 accountability evidence.
type AgentDecisionConsumer struct {
	proj  ProjectorPort
	inbox idempotent.Store
	ttl   time.Duration

	mu sync.Mutex
}

// NewAgentDecisionConsumer wires the projector + an idempotency inbox.
// When inbox is nil, an in-memory store is allocated.
func NewAgentDecisionConsumer(proj ProjectorPort, inbox idempotent.Store) *AgentDecisionConsumer {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &AgentDecisionConsumer{
		proj:  proj,
		inbox: inbox,
		ttl:   AgentDecisionInboxTTL,
	}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (c *AgentDecisionConsumer) SubscribedTopic() string {
	return TopicAgentDecisionLogged
}

// Handle processes one decoded message.
//
// `body` is the Pub/Sub message data; `attrs` is the envelope-derived
// message attributes. The subscriber prefers attribute values for
// envelope-mandatory fields (per chora-contracts envelope.proto).
//
// Idempotency: the event_id is the dedupe key. Re-delivery from
// at-least-once Pub/Sub is a no-op at this layer; the projector is also
// idempotent on EventID per its design.
//
// Returns nil on successful append. Returns an error on validation
// failure or downstream projector error. The caller (a Pub/Sub
// subscriber adapter) is expected to NACK on error so Pub/Sub retries.
func (c *AgentDecisionConsumer) Handle(
	ctx context.Context,
	body []byte,
	attrs AgentDecisionEnvelopeAttrs,
) error {
	if c == nil || c.proj == nil {
		return errors.New("events: AgentDecisionConsumer not initialised")
	}

	// FAIL LOUD (ADR-167 HARD REQUIREMENT #1): the topic is
	// Schema-Registry-bound with encoding=BINARY. proto.Unmarshal failure
	// returns an error so the message NACKs → DLQ. NO JSON fallback; NO
	// silent drop; Protobuf only.
	var msg observabilityv1.AgentDecisionLogged
	if err := proto.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("events: agent_decision proto decode: %w", err)
	}

	d := extractAgentDecision(&msg, attrs)

	if err := validateAgentDecision(d); err != nil {
		return err
	}

	// Dedupe key: prefer envelope idempotency_key (deterministic per
	// (assist_id, decision)), fall back to event_id.
	dedupeKey := d.IdempotencyKey
	if dedupeKey == "" {
		dedupeKey = d.EventID
	}

	return c.inbox.Process(ctx, dedupeKey, c.ttl, func() error {
		ev := projector.IncomingEvent{
			EventID:        d.EventID,
			TenantID:       d.TenantID,
			ImdaDimension:  expectedDimension, // canonical per ADR-141
			LifecycleStage: string(evidence.LifecycleRuntime),
			EventType:      "agent.decision.logged",
			// d.OccurredAt is decided_at (or the envelope) as RFC3339Nano;
			// an unparseable value yields zero, which the domain reads as now.
			OccurredAt:  parseRFC3339Nano(d.OccurredAt),
			Traceparent: d.Traceparent,

			// D1 accountability fields per projector.IncomingEvent shape.
			// AgentID is the REAL per-agent agid from the inbound event
			// (proto field 4) — NOT a hardcoded crew label. Mislabelling
			// every decision as "qgen_crew" corrupted the D1 evidence store;
			// the producer now emits the real agid (qgen_question /
			// qgen_critic / oe_evaluator / oe_moderator).
			AgentID:    d.Agid,
			OwnerGcid:  d.GCID,
			DecisionID: d.AssistID, // 1:1 with the assist invocation
			DecisionType: fmt.Sprintf(
				"qgen.quality_gate.%s",
				strings.ToLower(strings.TrimSpace(d.Decision)),
			),

			// Extension fields (proto 12-20) forwarded into
			// projector.IncomingEvent so the projector can stamp them
			// into the evidence row's Provenance — feeds /o/agents
			// Crews+Agents hierarchy + /o/governance Decision Traces
			// drilldown.
			CrewName:         d.CrewName,
			CrewID:           d.CrewID,
			IsResume:         d.IsResume,
			IsEvalRun:        d.IsEvalRun,
			AdapterVersion:   d.AdapterVersion,
			GuardrailOutcome: d.GuardrailOutcome,
			PromptTokens:     d.PromptTokens,
			CompletionTokens: d.CompletionTokens,
			CachedTokens:     d.CachedTokens,

			Provenance: map[string]any{
				"assist_id":         d.AssistID,
				"decision":          d.Decision,
				"attempt_count":     d.AttemptCount,
				"max_retries":       d.MaxRetries,
				"quality_warning":   d.QualityWarning,
				"critic_notes":      d.CriticNotes,
				"occurred_at":       d.OccurredAt,
				"tracestate":        d.Tracestate,
				"schema_version":    d.SchemaVersion,
				"crew_name":         d.CrewName,
				"crew_id":           d.CrewID,
				"is_resume":         d.IsResume,
				"is_eval_run":       d.IsEvalRun,
				"adapter_version":   d.AdapterVersion,
				"guardrail_outcome": d.GuardrailOutcome,
				"prompt_tokens":     d.PromptTokens,
				"completion_tokens": d.CompletionTokens,
				"cached_tokens":     d.CachedTokens,
			},
		}
		return c.proj.Project(ctx, ev)
	})
}

// extractAgentDecision maps the inbound AgentDecisionLogged proto into the
// projector-relevant decodedAgentDecision per the ADR-167 canonical
// mapping. The proto EventEnvelope (field 1) is AUTHORITATIVE for the
// envelope-mandatory fields; the routing attrs are read only as a fallback
// when the proto envelope is nil (or a given field is blank on it).
func extractAgentDecision(
	msg *observabilityv1.AgentDecisionLogged,
	attrs AgentDecisionEnvelopeAttrs,
) decodedAgentDecision {
	env := msg.GetEnvelope()

	d := decodedAgentDecision{
		// Proto envelope wins; routing attrs are the fallback.
		EventID:            firstNonBlank(env.GetEventId(), attrs.EventID),
		IdempotencyKey:     firstNonBlank(env.GetIdempotencyKey(), attrs.IdempotencyKey),
		TenantID:           firstNonBlank(env.GetTenantId(), attrs.TenantID),
		GCID:               firstNonBlank(env.GetGcid(), attrs.GCID),
		Traceparent:        firstNonBlank(env.GetTraceparent(), attrs.Traceparent),
		Tracestate:         firstNonBlank(env.GetTracestate(), attrs.Tracestate),
		ChoraImdaDimension: firstNonBlank(env.GetChoraImdaDimension(), attrs.ChoraImdaDimension),

		// decision_id == invocation_id == assist_id (ADR-167 mapping).
		AssistID: firstNonBlank(msg.GetDecisionId(), msg.GetInvocationId()),
		// The REAL per-agent agid (proto field 4) — the same value the
		// observability service persists as agent_id. Producer contract
		// guarantees non-empty.
		Agid:        msg.GetAgid(),
		CriticNotes: msg.GetOutputSummary(),

		// Extension fields (proto 12-20) straight through.
		CrewName:         firstNonBlank(msg.GetCrewName(), attrs.CrewName),
		CrewID:           msg.GetCrewId(),
		IsResume:         msg.GetIsResume(),
		IsEvalRun:        msg.GetIsEvalRun(),
		AdapterVersion:   msg.GetAdapterVersion(),
		GuardrailOutcome: msg.GetGuardrailOutcome(),
		PromptTokens:     msg.GetPromptTokens(),
		CompletionTokens: msg.GetCompletionTokens(),
		CachedTokens:     msg.GetCachedTokens(),
	}

	// schema_version: proto envelope int32 (when non-zero) wins, else attrs.
	if sv := env.GetSchemaVersion(); sv != 0 {
		d.SchemaVersion = strconv.FormatInt(int64(sv), 10)
	} else {
		d.SchemaVersion = attrs.SchemaVersion
	}

	// decided_at → occurred_at (RFC3339Nano). decided_at is the canonical
	// per-decision clock per the ADR-167 mapping; fall back to the envelope
	// occurred_at when decided_at is unset.
	if t := msg.GetDecidedAt(); t != nil {
		d.OccurredAt = t.AsTime().UTC().Format(time.RFC3339Nano)
	} else if t := env.GetOccurredAt(); t != nil {
		d.OccurredAt = t.AsTime().UTC().Format(time.RFC3339Nano)
	}

	// qgen-specific detail rides the attributes map (proto field 21).
	a := msg.GetAttributes()
	d.Decision = a["decision"]
	d.AttemptCount = atoiOrZero(a["attempt_count"])
	d.MaxRetries = atoiOrZero(a["max_retries"])
	d.QualityWarning = parseBool(a["quality_warning"])

	return d
}

// atoiOrZero parses a base-10 int, returning 0 on blank/parse failure. The
// attributes map carries qgen counts as strings per the ADR-167 mapping.
func atoiOrZero(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// parseBool maps the attributes-map "true"/"false" string into a bool.
func parseBool(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "true")
}

// HandleEnvelope is a convenience wrapper for the in-process bus +
// integration tests. Post-ADR-167 the wire shape is a self-contained
// BINARY-protobuf AgentDecisionLogged whose field-1 EventEnvelope is
// authoritative, so the in-process path carries the same proto bytes the
// broker delivers — no separate JSON envelope wrapper. Routing attrs are
// empty here; the proto envelope supplies all envelope-mandatory fields.
func (c *AgentDecisionConsumer) HandleEnvelope(
	ctx context.Context,
	raw []byte,
) error {
	return c.Handle(ctx, raw, AgentDecisionEnvelopeAttrs{})
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func validateAgentDecision(d decodedAgentDecision) error {
	dim := strings.ToLower(strings.TrimSpace(d.ChoraImdaDimension))
	if strings.TrimSpace(d.EventID) == "" {
		return errors.New("events: agent_decision envelope event_id required")
	}
	if strings.TrimSpace(d.TenantID) == "" {
		return errors.New("events: agent_decision envelope tenant_id required")
	}
	if strings.TrimSpace(d.AssistID) == "" {
		return errors.New("events: agent_decision payload assist_id required (decision_id/invocation_id)")
	}
	if strings.TrimSpace(d.Decision) == "" {
		return errors.New("events: agent_decision attributes[decision] required")
	}
	if dim != expectedDimension {
		return fmt.Errorf(
			"events: agent_decision unexpected imda_dimension %q (want %q)",
			dim, expectedDimension,
		)
	}
	return nil
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// -----------------------------------------------------------------------------
// InMemoryProjector — test double for ProjectorPort.
// -----------------------------------------------------------------------------

// RecordedDecision captures one Project call for assertions.
type RecordedDecision struct {
	EventID       string
	TenantID      string
	AgentID       string
	OwnerGcid     string
	DecisionID    string
	DecisionType  string
	Provenance    map[string]any
	ImdaDimension string
	Traceparent   string
}

// InMemoryProjector is an in-memory ProjectorPort for tests.
type InMemoryProjector struct {
	mu        sync.Mutex
	recorded  []RecordedDecision
	failNext  bool
	failError error
}

// NewInMemoryProjector returns a fresh in-memory projector.
func NewInMemoryProjector() *InMemoryProjector {
	return &InMemoryProjector{recorded: make([]RecordedDecision, 0, 4)}
}

// Project records the event in memory + returns nil (or a stubbed error
// if SetFailNext was called).
func (p *InMemoryProjector) Project(_ context.Context, ev projector.IncomingEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext {
		p.failNext = false
		if p.failError != nil {
			return p.failError
		}
		return errors.New("inmem-projector: forced failure")
	}
	p.recorded = append(p.recorded, RecordedDecision{
		EventID:       ev.EventID,
		TenantID:      ev.TenantID,
		AgentID:       ev.AgentID,
		OwnerGcid:     ev.OwnerGcid,
		DecisionID:    ev.DecisionID,
		DecisionType:  ev.DecisionType,
		Provenance:    ev.Provenance,
		ImdaDimension: ev.ImdaDimension,
		Traceparent:   ev.Traceparent,
	})
	return nil
}

// Recorded returns a defensive copy of all recorded events.
func (p *InMemoryProjector) Recorded() []RecordedDecision {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]RecordedDecision, len(p.recorded))
	copy(out, p.recorded)
	return out
}

// SetFailNext arms the projector to return an error on the next Project
// call. Optional err overrides the default forced failure message.
func (p *InMemoryProjector) SetFailNext(b bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failNext = b
	p.failError = err
}
