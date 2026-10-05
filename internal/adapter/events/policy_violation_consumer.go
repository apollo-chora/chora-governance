// PolicyViolationConsumer drains `chora.governance.policy.violation_detected.v1`
// into IMDA D3 (safety_and_robustness) `policy_violation_log` evidence: the
// consumer half of requirement G2 (ADR-152 amendment 2026-08-07).
//
// Producer of record: chora-model-gateway. Every Cloud Model Armor BLOCK at the
// single un-bypassable LLM chokepoint (ADR-163) enqueues one
// PolicyViolationDetected onto the shared chora-observability outbox, which the
// dispatcher publishes by topic. See
// services/chora-model-gateway/internal/adapter/pg/pg_violation.go.
//
// WIRE CONSTRAINT. The topic is bound to a BINARY PROTOCOL_BUFFER Pub/Sub
// schema (chora-governance-policy-violation_detected-v1), so the body is a
// proto.Marshal of governance.v1.PolicyViolationDetected. The chora-sharing
// sibling that decodes this topic as JSON is unwired dead code and its
// subscription does not exist live, and it is NOT a template for this file.
//
// FIELD MAPPING NOTE. The ratified proto carries no agent, leg or verdict
// field, and adding one needs a Pub/Sub schema revision (an additive proto
// field 400s at publish until the revision lands). The producer therefore packs
// those three facts into a stable key=value tail on `description`, which this
// consumer parses. `agent_id` is the one the evidence row cannot omit:
// evidence.NewPolicyViolation requires it non-blank.
//
// WHY AN UNPARSEABLE DESCRIPTION STILL WRITES A ROW. G2 exists so that a real
// refusal becomes durable governance evidence. Dropping a genuine Armor block
// because the producer's wording drifted would defeat the requirement it is
// measured on, so an unattributed violation is recorded under the explicit
// AgentIDUnattributed marker, with an `agent_attribution: absent` payload key
// and a loud WARN naming the violation. The verbatim description always rides
// in the payload, so no fact is lost and nothing is invented. Fields the row
// cannot be honest without (event_id, tenant_id, detector, policy_name)
// still fail loud (NACK, then the DLQ, which has a drain subscription).
//
// Cross-DB queries forbidden: chora-governance reads only its own DB, and the
// RLS-scoped write is performed by the evidence repository's WithTenantTx.
package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-common/idempotent"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// TopicPolicyViolationDetected is the canonical provisioned violation topic.
const TopicPolicyViolationDetected = "chora.governance.policy.violation_detected.v1"

// PolicyViolationInboxTTL is the dedupe-key retention window.
const PolicyViolationInboxTTL = 24 * time.Hour

// safetyDimension is the canonical D3 IMDA dimension (ADR-141).
const safetyDimension = "safety_and_robustness"

// policyViolationEventType routes the projector to policy_violation_log
// (routeD3 matches on EventType contains "policy_violation").
const policyViolationEventType = "policy_violation_detected"

// AgentIDUnattributed marks a violation whose producer did not state a calling
// agent. It is a statement that attribution is absent, never a guess at who
// called; the verbatim description is preserved in the evidence payload.
const AgentIDUnattributed = "unattributed"

// PolicyViolationAttrs are the envelope-derived Pub/Sub message attributes
// (fallback only; the proto envelope is authoritative).
type PolicyViolationAttrs struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
}

// PolicyViolationConsumer ingests PolicyViolationDetected events + projects
// them into D3 policy_violation_log evidence via the governance projector.
type PolicyViolationConsumer struct {
	proj  ProjectorPort
	inbox idempotent.Store
	ttl   time.Duration
}

// NewPolicyViolationConsumer wires the projector + an idempotency inbox.
func NewPolicyViolationConsumer(proj ProjectorPort, inbox idempotent.Store) *PolicyViolationConsumer {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &PolicyViolationConsumer{proj: proj, inbox: inbox, ttl: PolicyViolationInboxTTL}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (c *PolicyViolationConsumer) SubscribedTopic() string { return TopicPolicyViolationDetected }

// Handle decodes one BINARY PolicyViolationDetected message and projects a
// single policy_violation_log row. Idempotent on the envelope idempotency_key
// (falling back to event_id) via the inbox AND the evidence repo's append-only
// dedupe on event_id.
func (c *PolicyViolationConsumer) Handle(ctx context.Context, body []byte, attrs PolicyViolationAttrs) error {
	if c == nil || c.proj == nil {
		return errors.New("events: PolicyViolationConsumer not initialised")
	}

	var msg governancev1.PolicyViolationDetected
	if err := proto.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("events: policy_violation proto decode: %w", err)
	}

	env := msg.GetEnvelope()
	eventID := strings.TrimSpace(firstNonBlank(env.GetEventId(), attrs.EventID))
	tenantID := strings.TrimSpace(firstNonBlank(env.GetTenantId(), attrs.TenantID))
	idempotencyKey := strings.TrimSpace(firstNonBlank(env.GetIdempotencyKey(), attrs.IdempotencyKey))
	detector := strings.TrimSpace(msg.GetDetector())
	policyName := strings.TrimSpace(msg.GetPolicyId())

	if eventID == "" {
		return errors.New("events: policy_violation envelope event_id required")
	}
	if tenantID == "" {
		return errors.New("events: policy_violation envelope tenant_id required (the evidence write is RLS-scoped on it)")
	}
	if detector == "" {
		return errors.New("events: policy_violation detector required")
	}
	if policyName == "" {
		return errors.New("events: policy_violation policy_id required (it names the policy that fired)")
	}

	severity, err := policyViolationSeverity(msg.GetViolationSeverity())
	if err != nil {
		return err
	}

	description := msg.GetDescription()
	facts := parseViolationDescription(description)
	agentID := facts["agent_id"]
	attribution := "present"
	if agentID == "" {
		agentID = AgentIDUnattributed
		attribution = "absent"
		slog.WarnContext(ctx, "governance: policy_violation description carries no agent_id tail; recording unattributed",
			"violation_id", msg.GetViolationId(),
			"event_id", eventID,
			"tenant_id", tenantID,
			"detector", detector,
		)
	}

	stage := strings.TrimSpace(env.GetImdaLifecycleStage())
	if stage == "" {
		stage = string(evidence.LifecycleRuntime)
	}

	dedupeKey := idempotencyKey
	if dedupeKey == "" {
		dedupeKey = eventID
	}

	return c.inbox.Process(ctx, dedupeKey, c.ttl, func() error {
		ev := projector.IncomingEvent{
			EventID:        eventID,
			TenantID:       tenantID,
			ImdaDimension:  firstNonBlank(strings.TrimSpace(env.GetChoraImdaDimension()), safetyDimension),
			LifecycleStage: stage,
			EventType:      policyViolationEventType,
			Traceparent:    env.GetTraceparent(),
			// The instant Armor REFUSED, not the instant this consumer ran.
			OccurredAt: envelopeTime(msg.GetDetectedAt(), env.GetOccurredAt()),
			AgentID:    agentID,
			PolicyName: policyName,
			Severity:   severity,
			Detector:   detector,
			Payload: map[string]any{
				"violation_id":      msg.GetViolationId(),
				"description":       description,
				"resource_uri":      msg.GetResourceUri(),
				"subject_gcid":      msg.GetSubjectGcid(),
				"policy_kind":       msg.GetPolicyKind().String(),
				"leg":               facts["leg"],
				"invocation_id":     facts["invocation_id"],
				"verdict":           facts["verdict"],
				"agent_attribution": attribution,
				"source_service":    env.GetSourceService(),
				"detected_at":       msg.GetDetectedAt().AsTime().UTC().Format(time.RFC3339Nano),
			},
		}
		return c.proj.Project(ctx, ev)
	})
}

// HandleEnvelope is the in-process / test convenience wrapper.
func (c *PolicyViolationConsumer) HandleEnvelope(ctx context.Context, raw []byte) error {
	return c.Handle(ctx, raw, PolicyViolationAttrs{})
}

// policyViolationSeverity maps the proto enum onto the lowercase string the
// evidence row stores. The map is TOTAL over the ratified enum; an unrecognised
// value is a contract change and fails loud rather than being coerced into a
// plausible-looking severity that an auditor would then trust.
func policyViolationSeverity(s governancev1.ViolationSeverity) (string, error) {
	switch s {
	case governancev1.ViolationSeverity_VIOLATION_SEVERITY_UNSPECIFIED:
		return "unspecified", nil
	case governancev1.ViolationSeverity_VIOLATION_SEVERITY_INFO:
		return "info", nil
	case governancev1.ViolationSeverity_VIOLATION_SEVERITY_LOW:
		return "low", nil
	case governancev1.ViolationSeverity_VIOLATION_SEVERITY_MEDIUM:
		return "medium", nil
	case governancev1.ViolationSeverity_VIOLATION_SEVERITY_HIGH:
		return "high", nil
	case governancev1.ViolationSeverity_VIOLATION_SEVERITY_CRITICAL:
		return "critical", nil
	default:
		return "", fmt.Errorf("events: policy_violation unmapped violation_severity %d; the proto enum grew and this map must grow with it", int32(s))
	}
}

// parseViolationDescription lifts the producer's stable key=value tail out of
// the free-text description, plus the leg from its fixed prefix. Producer:
// chora-model-gateway domain.PolicyViolationEvent.Description(), which renders
//
//	Cloud Model Armor refused the call at the PRE leg: agent_id=<id> invocation_id=<id> verdict=<v>
//
// Missing keys come back absent rather than guessed; the caller decides what a
// missing key means.
func parseViolationDescription(desc string) map[string]string {
	out := map[string]string{}
	if strings.TrimSpace(desc) == "" {
		return out
	}
	for _, tok := range strings.Fields(desc) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok || v == "" {
			continue
		}
		switch k {
		case "agent_id", "invocation_id", "verdict":
			out[k] = v
		}
	}
	if _, after, ok := strings.Cut(desc, "at the "); ok {
		if leg, _, ok := strings.Cut(after, " leg"); ok {
			if leg = strings.TrimSpace(leg); leg != "" {
				out["leg"] = leg
			}
		}
	}
	return out
}
