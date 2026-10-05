// AuditEgressSubscriber routes chora.governance.audit.external_egress.v1 from
// chora-model-gateway into the chora-governance audit_log as an append-only
// hash-chained entry — the IMDA D2 transparency + D1 accountability evidence
// trail for every learner-triggered external web egress (ADR-231 / ADR-220).
//
// Source-of-truth:
//   - chora-contracts/proto/events/governance/audit.proto §ExternalEgressAudited
//   - chora-model-gateway .../adapter/pg/pg_grounded.go (BINARY emitter; the
//     proto Envelope is field 1, the canonical envelope source per ADR-167)
//   - ADR-231 Amendment (2026-07-17, Open Question 3 closed): dedicated egress
//     audit event RATIFIED into the hash-chained audit_log, payments-audit parity
//   - .claude/rules/ddd-enforcement.md (audit aggregate, append-only)
//   - CHO-2245
//
// Topic (v1): chora.governance.audit.external_egress.v1
//
// Publisher side: chora-model-gateway emits BINARY proto via its
// chora_observability outbox. Subscriber side: this file. Per
// [[feedback-d6-resilience-first-class]] Pillar 2: Handle returns error on
// failure so the caller's Pub/Sub adapter Nacks for redelivery (DLQ on
// max_delivery_attempts).
//
// Hexagonal: INBOUND adapter; depends only on the audit.Repository port. No
// cross-DB queries; chora_governance is the only DB this touches.
//
// Schema fit: audit_log (migration 0001_initial.sql) is event_kind-agnostic.
// The `action` column carries the discriminator (ActionExternalEgress),
// `subject_type`/`subject_id` index the calling agent, and the full proto
// payload is serialised as JSON into `after_state`. No new migration needed —
// the existing audit aggregate accepts this kind cleanly (payments-audit parity).
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

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"
	"github.com/apollo-chora/chora-common/idempotent"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

// -----------------------------------------------------------------------------
// Topic + action constants (canonical names per the contracts proto + emitter).
// -----------------------------------------------------------------------------

// TopicExternalEgressAudited is the canonical topic chora-model-gateway emits to
// (matches externalEgressTopic in pg_grounded.go).
const TopicExternalEgressAudited = "chora.governance.audit.external_egress.v1"

// ActionExternalEgress is the audit_log.action discriminator for a grounded
// external-web egress. The audit aggregate's VARCHAR(128) action accepts it
// without schema extension (same posture as the payments audit actions).
const ActionExternalEgress = "external_egress"

// resourceExternalEgress names the audited resource (the familiar's external
// web egress through the model-gateway chokepoint).
const resourceExternalEgress = "familiar.external_egress"

// AuditEgressInboxTTL is the dedupe-key retention window. Matches the
// AuditPaymentsInboxTTL / AgentDecisionInboxTTL convention.
const AuditEgressInboxTTL = 24 * time.Hour

// -----------------------------------------------------------------------------
// AuditEgressEnvelopeAttrs — envelope-derived Pub/Sub message attributes the
// dispatcher copies off the outbox row. Per ADR-167 the proto body is the
// CANONICAL envelope source; these attributes are advisory routing copies the
// subscriber consults only as a fallback when a body field is blank (mirrors
// AuditPaymentsEnvelopeAttrs).
// -----------------------------------------------------------------------------
type AuditEgressEnvelopeAttrs struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	Traceparent    string
	Tracestate     string
	SchemaVersion  string
}

// -----------------------------------------------------------------------------
// eventbus binding helpers — mirror the other governance subscribers so
// cmd/server/main.go wires this topic with the same shape.
// -----------------------------------------------------------------------------

// AuditEgressAttrsFromEnvelope lifts the eventbus envelope into the typed
// AuditEgressEnvelopeAttrs shape. Missing fields yield zero values; the
// subscriber's validation rejects empty mandatory fields downstream so a
// broken envelope surfaces as a clear error rather than a silent insert.
func AuditEgressAttrsFromEnvelope(env envelope.Envelope) AuditEgressEnvelopeAttrs {
	return AuditEgressEnvelopeAttrs{
		EventID:        env.EventID,
		IdempotencyKey: env.IdempotencyKey,
		TenantID:       env.TenantID,
		GCID:           env.GCID,
		Traceparent:    env.Traceparent,
		Tracestate:     env.Tracestate,
		SchemaVersion:  strconv.FormatInt(int64(env.SchemaVersion), 10),
	}
}

// -----------------------------------------------------------------------------
// AuditEgressSubscriber — appends one audit_log entry per egress event.
// Depends only on the audit.Repository port (hexagonal).
// -----------------------------------------------------------------------------
type AuditEgressSubscriber struct {
	repo  audit.Repository
	inbox idempotent.Store
	ttl   time.Duration

	mu sync.Mutex
}

// NewAuditEgressSubscriber wires the audit repo + idempotency inbox. When inbox
// is nil, an in-memory store is allocated.
func NewAuditEgressSubscriber(repo audit.Repository, inbox idempotent.Store) *AuditEgressSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &AuditEgressSubscriber{
		repo:  repo,
		inbox: inbox,
		ttl:   AuditEgressInboxTTL,
	}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (s *AuditEgressSubscriber) SubscribedTopic() string {
	return TopicExternalEgressAudited
}

// HandleExternalEgressAudited subscribes to chora.governance.audit.external_egress.v1.
//   - subject = (agent, agent_id) — the calling skill that reached the web
//   - decision = mapped TOTALLY from the payload AuditResult (fail-loud on
//     UNSPECIFIED / out-of-contract; ANOMALY = allowed-but-flagged → permitted)
func (s *AuditEgressSubscriber) HandleExternalEgressAudited(
	ctx context.Context,
	body []byte,
	attrs AuditEgressEnvelopeAttrs,
) error {
	if err := s.checkInitialised(); err != nil {
		return err
	}

	var payload governancev1.ExternalEgressAudited
	if err := proto.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("events: external_egress decode: %w", err)
	}

	// Canonical source = proto body (ADR-167); attrs are advisory routing copies
	// preferred only as a fallback when the body field is blank. The envelope is
	// embedded as field 1; getters are nil-safe when it is absent.
	env := payload.GetEnvelope()
	tenantID := firstNonBlank(env.GetTenantId(), attrs.TenantID)
	actorGCID := firstNonBlank(payload.GetActorGcid(), env.GetGcid(), attrs.GCID)
	eventID := firstNonBlank(env.GetEventId(), payload.GetAuditId(), attrs.EventID)
	traceparent := firstNonBlank(env.GetTraceparent(), attrs.Traceparent)
	tracestate := firstNonBlank(env.GetTracestate(), attrs.Tracestate)

	if err := validateEnvelope(eventID, tenantID); err != nil {
		return err
	}

	// TOTAL map over the AuditResult contract — UNSPECIFIED / unknown are loud
	// errors (NACK), never a silent default decision.
	decision, resultLabel, err := egressDecision(payload.GetResult())
	if err != nil {
		return err
	}

	// Prefer the deterministic idempotency_key; fall back to event_id.
	dedupeKey := strings.TrimSpace(attrs.IdempotencyKey)
	if dedupeKey == "" {
		dedupeKey = eventID
	}
	return s.inbox.Process(ctx, dedupeKey, s.ttl, func() error {
		payloadJSON, err := marshalProtoJSON(&payload)
		if err != nil {
			return err
		}
		ev, err := audit.New(audit.NewParams{
			TenantID:    tenantID,
			Gcid:        actorGCID,
			Action:      ActionExternalEgress,
			Resource:    resourceExternalEgress,
			Decision:    decision,
			Reason:      egressReason(resultLabel, &payload),
			SubjectType: "agent",
			SubjectID:   strings.TrimSpace(payload.GetAgentId()),
			ActorGcid:   actorGCID,
			After:       payloadJSON,
			Traceparent: traceparent,
			Tracestate:  tracestate,
		})
		if err != nil {
			return fmt.Errorf("events: external_egress audit.New: %w", err)
		}
		if appendErr := s.repo.Append(ctx, ev); appendErr != nil {
			// ErrAlreadyExists is a no-op — Pub/Sub replays land here when the
			// dedupe-key path is bypassed. Treat as success so the message is Acked.
			if errors.Is(appendErr, audit.ErrAlreadyExists) {
				return nil
			}
			return fmt.Errorf("events: external_egress append: %w", appendErr)
		}
		return nil
	})
}

// -----------------------------------------------------------------------------
// eventbus binding helpers — mirror the other governance subscribers so
// cmd/server/main.go wires this topic with the same shape.
// -----------------------------------------------------------------------------

// HandleExternalEgressMessage dispatches one eventbus delivery. A handler
// error nacks so the bus redelivers (DLQ after MaxDeliver attempts).
func HandleExternalEgressMessage(
	ctx context.Context,
	sub *AuditEgressSubscriber,
	msg eventbus.Message,
) error {
	if sub == nil {
		return errors.New("events: AuditEgressSubscriber is nil; cannot dispatch")
	}

	attrs := AuditEgressAttrsFromEnvelope(msg.Envelope)
	return sub.HandleExternalEgressAudited(ctx, msg.Payload, attrs)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (s *AuditEgressSubscriber) checkInitialised() error {
	if s == nil || s.repo == nil {
		return errors.New("events: AuditEgressSubscriber not initialised")
	}
	return nil
}

// egressDecision maps the payload AuditResult to the binary audit Decision,
// TOTALLY over the enum contract. ANOMALY is "allowed but flagged" — the egress
// dispatched, so it records as Permitted with the anomaly carried in the reason
// (and the raw result preserved in the After payload). UNSPECIFIED (the unset
// sentinel — a publisher that never set a result is a bug) and any
// out-of-contract value are loud errors so the message NACKs rather than
// recording a fabricated decision.
func egressDecision(r governancev1.AuditResult) (audit.Decision, string, error) {
	switch r {
	case governancev1.AuditResult_AUDIT_RESULT_ALLOWED:
		return audit.DecisionPermitted, "allowed", nil
	case governancev1.AuditResult_AUDIT_RESULT_DENIED:
		return audit.DecisionDenied, "denied", nil
	case governancev1.AuditResult_AUDIT_RESULT_ANOMALY:
		return audit.DecisionPermitted, "anomaly", nil
	case governancev1.AuditResult_AUDIT_RESULT_UNSPECIFIED:
		return "", "", errors.New("events: external_egress result UNSPECIFIED (publisher bug)")
	default:
		return "", "", fmt.Errorf("events: external_egress unknown AuditResult %d", int32(r))
	}
}

// egressReason renders an auditor-readable one-line summary for
// audit_log.reason. The load-bearing full detail (queries, verdicts, hashes)
// lives in the After JSONB payload.
func egressReason(resultLabel string, p *governancev1.ExternalEgressAudited) string {
	reason := fmt.Sprintf(
		"external egress %s: agent=%s action_code=%s citations=%d",
		resultLabel,
		strings.TrimSpace(p.GetAgentId()),
		strings.TrimSpace(p.GetActionCode()),
		p.GetCitationCount(),
	)
	if dr := strings.TrimSpace(p.GetDenialReason()); dr != "" {
		reason += "; denial_reason=" + dr
	}
	if pre := strings.TrimSpace(p.GetModelArmorVerdictPre()); pre != "" {
		reason += "; armor_pre=" + pre
	}
	if post := strings.TrimSpace(p.GetModelArmorVerdictPost()); post != "" {
		reason += "; armor_post=" + post
	}
	return reason
}
