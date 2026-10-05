// EvidenceRecordedSubscriber routes chora.governance.evidence.recorded.v1 —
// the SHARED, cross-domain IMDA-evidence topic every producing domain emits
// into (per Tier 5 D17 + chora-contracts/proto/events/governance/evidence.proto)
// — into the chora-governance audit_log as an append-only hash-chained entry:
// the IMDA D1 accountability + D2 transparency evidence trail.
//
// Source-of-truth:
//   - chora-contracts/proto/events/governance/evidence.proto §EvidenceRecorded
//     (envelope embedded as field 1; the IMDA dimension + lifecycle stage ride
//     the EventEnvelope fields 14/15, NOT the message body)
//   - Producers (BINARY proto via outbox):
//     services/chora-observability/cmd/server/familiar_growth_evidence_publisher.go
//     (Familiar-Growth audit lane, CHO-2257 — the live producer)
//     services/chora-identity/internal/adapter/events/imda_evidence.go
//     (the original cross-domain producer: KYC / role-grant / federation)
//   - .claude/rules/ddd-enforcement.md (audit aggregate, append-only)
//   - CHO-2260
//
// Topic (v1): chora.governance.evidence.recorded.v1  (Schema-Registry-bound,
// encoding=BINARY, schema chora-governance-evidence-recorded-v1 — verified in
// deployed reality 2026-07-17). A JSON assumption FAILS: an additive proto
// field 400s AT PUBLISH and never reaches a DLQ.
//
// Sink decision (CHO-2260): EvidenceRecorded is a GENERIC per-action evidence
// event — it carries evidence_type + source_event_type + policy_reference +
// additional_fields, but NONE of the structured fields the D1/D2 evidence
// projector aggregates require (accountability_evidence needs agent_id /
// owner_gcid / decision_id / decision_type, all NOT NULL; decision_explanation
// needs decision_id / explanation_md). Routing the generic wire through the
// projector would therefore reject 100% of real producer events — a fresh
// shredder. audit_log is kind-agnostic (the `action` column carries the
// discriminator), append-only, per-tenant hash-chained, RLS-isolated — the
// same sink AuditEgressSubscriber (CHO-2245) and AuditPaymentsSubscriber use
// for their IMDA evidence trails — so the generic evidence lands durably
// WITHOUT fabricating fields. See the story comment for the alternative
// (extend the producer contract + projector) the owner may prefer instead.
//
// Per [[feedback-d6-resilience-first-class]] Pillar 2: Handle returns error on
// failure so the caller's event bus adapter Nacks for redelivery (DLQ on
// max_delivery_attempts). Idempotency: redelivery is deduped on the inbox key
// (idempotency_key → event_id) — audit.New mints a fresh audit_log PK per
// Append, so the DB PK does not dedupe redeliveries; the inbox does.
//
// Hexagonal: INBOUND adapter; depends only on the audit.Repository port. No
// cross-DB queries; chora_governance is the only DB this touches. Schema fit:
// audit_log (migration 0001_initial.sql) accepts this kind without any new
// migration — action=ActionEvidenceRecorded, subject_type="evidence",
// subject_id=evidence_type (the indexed fine discriminator), and the full proto
// payload serialised as JSON into after_state.
package events

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"
	"github.com/apollo-chora/chora-common/idempotent"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

// -----------------------------------------------------------------------------
// Topic + action constants.
// -----------------------------------------------------------------------------

// TopicEvidenceRecorded is the canonical provisioned event bus topic for the
// shared IMDA-evidence event. Centralised in chora-local (platform host).
const TopicEvidenceRecorded = "chora.governance.evidence.recorded.v1"

// ActionEvidenceRecorded is the audit_log.action discriminator (a stable,
// low-cardinality class shared by every evidence-recorded row). The fine
// per-event discriminator is the evidence_type, stamped into subject_id and
// preserved in after_state.
const ActionEvidenceRecorded = "evidence_recorded"

// resourceEvidenceRecorded names the audited resource — a recorded piece of
// IMDA governance evidence.
const resourceEvidenceRecorded = "governance.evidence"

// EvidenceRecordedInboxTTL is the dedupe-key retention window. Matches the
// AuditEgressInboxTTL / AuditPaymentsInboxTTL convention.
const EvidenceRecordedInboxTTL = 24 * time.Hour

// -----------------------------------------------------------------------------
// EvidenceRecordedEnvelopeAttrs — envelope-derived event bus message attributes
// the dispatcher copies off the outbox row. Per ADR-167 the proto Envelope
// (field 1) is the CANONICAL source; these attributes are advisory routing
// copies the subscriber consults only as a fallback when a body field is blank.
// -----------------------------------------------------------------------------
type EvidenceRecordedEnvelopeAttrs struct {
	EventID            string
	IdempotencyKey     string
	TenantID           string
	GCID               string
	Traceparent        string
	Tracestate         string
	ChoraImdaDimension string
	SchemaVersion      string
}

// EvidenceRecordedAttrsFromEnvelope lifts the eventbus envelope into the
// typed EvidenceRecordedEnvelopeAttrs shape. Missing fields yield zero
// values; the subscriber's validation rejects empty mandatory fields
// downstream so a broken envelope surfaces as a clear error rather than a
// silent insert.
func EvidenceRecordedAttrsFromEnvelope(env envelope.Envelope) EvidenceRecordedEnvelopeAttrs {
	return EvidenceRecordedEnvelopeAttrs{
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

// -----------------------------------------------------------------------------
// EvidenceRecordedSubscriber — appends one audit_log entry per evidence event.
// Depends only on the audit.Repository port (hexagonal).
// -----------------------------------------------------------------------------
type EvidenceRecordedSubscriber struct {
	repo  audit.Repository
	inbox idempotent.Store
	ttl   time.Duration
}

// NewEvidenceRecordedSubscriber wires the audit repo + idempotency inbox. When
// inbox is nil, an in-memory store is allocated.
func NewEvidenceRecordedSubscriber(repo audit.Repository, inbox idempotent.Store) *EvidenceRecordedSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &EvidenceRecordedSubscriber{
		repo:  repo,
		inbox: inbox,
		ttl:   EvidenceRecordedInboxTTL,
	}
}

// SubscribedTopic returns the canonical topic this subscriber binds to.
func (s *EvidenceRecordedSubscriber) SubscribedTopic() string {
	return TopicEvidenceRecorded
}

// HandleEvidenceRecorded subscribes to chora.governance.evidence.recorded.v1.
//   - subject = (evidence, evidence_type) — the canonical governed-action label
//   - decision = permitted (the governed action occurred + was recorded)
//   - the IMDA dimension + lifecycle stage are read off the envelope and folded
//     into the reason + preserved in the After payload
func (s *EvidenceRecordedSubscriber) HandleEvidenceRecorded(
	ctx context.Context,
	body []byte,
	attrs EvidenceRecordedEnvelopeAttrs,
) error {
	if err := s.checkInitialised(); err != nil {
		return err
	}

	// FAIL LOUD: the topic is Schema-Registry-bound with encoding=BINARY.
	// proto.Unmarshal failure returns an error so the message NACKs → DLQ.
	// NO JSON fallback; NO silent drop; Protobuf only.
	var payload governancev1.EvidenceRecorded
	if err := proto.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("events: evidence_recorded decode: %w", err)
	}

	// Canonical source = proto Envelope (ADR-167); attrs are advisory routing
	// copies preferred only as a fallback when the body field is blank.
	env := payload.GetEnvelope()
	tenantID := firstNonBlank(env.GetTenantId(), attrs.TenantID)
	actorGCID := firstNonBlank(env.GetGcid(), attrs.GCID)
	eventID := firstNonBlank(env.GetEventId(), attrs.EventID)
	traceparent := firstNonBlank(env.GetTraceparent(), attrs.Traceparent)
	tracestate := firstNonBlank(env.GetTracestate(), attrs.Tracestate)
	dimension := firstNonBlank(env.GetChoraImdaDimension(), attrs.ChoraImdaDimension)
	lifecycle := strings.TrimSpace(env.GetImdaLifecycleStage())

	evidenceType := strings.TrimSpace(payload.GetEvidenceType())
	sourceEventType := strings.TrimSpace(payload.GetSourceEventType())
	policyRef := strings.TrimSpace(payload.GetPolicyReference())

	// Mandatory-field validation — fail loud, never a silent insert.
	if strings.TrimSpace(eventID) == "" {
		return errors.New("events: evidence_recorded envelope event_id required")
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("events: evidence_recorded envelope tenant_id required")
	}
	// audit_log.gcid is UUID NOT NULL — a GCID-less event cannot be recorded as
	// an accountability row, so reject loudly rather than fabricate a subject.
	if strings.TrimSpace(actorGCID) == "" {
		return errors.New("events: evidence_recorded envelope gcid required")
	}
	// evidence_type is the canonical governed-action label + the audit subject
	// discriminator; a blank one is a publisher bug.
	if evidenceType == "" {
		return errors.New("events: evidence_recorded payload evidence_type required")
	}

	// Prefer the deterministic idempotency_key; fall back to event_id. Both ride
	// the envelope; the inbox is the redelivery guard (audit.New mints a fresh
	// audit_log PK, so the DB PK does not dedupe replays).
	dedupeKey := firstNonBlank(attrs.IdempotencyKey, env.GetIdempotencyKey(), eventID)

	return s.inbox.Process(ctx, dedupeKey, s.ttl, func() error {
		payloadJSON, err := marshalProtoJSON(&payload)
		if err != nil {
			return err
		}
		ev, err := audit.New(audit.NewParams{
			TenantID:    tenantID,
			Gcid:        actorGCID,
			Action:      ActionEvidenceRecorded,
			Resource:    resourceEvidenceRecorded,
			Decision:    audit.DecisionPermitted,
			Reason:      evidenceRecordedReason(evidenceType, sourceEventType, dimension, lifecycle, policyRef),
			SubjectType: "evidence",
			SubjectID:   evidenceType, // indexed via (subject_type, subject_id)
			ActorGcid:   actorGCID,
			After:       payloadJSON,
			Traceparent: traceparent,
			Tracestate:  tracestate,
		})
		if err != nil {
			return fmt.Errorf("events: evidence_recorded audit.New: %w", err)
		}
		if appendErr := s.repo.Append(ctx, ev); appendErr != nil {
			// ErrAlreadyExists is a no-op — a defensive belt for the rare case a
			// replay reaches Append with a colliding event_id. Treat as success
			// so the message is Acked.
			if errors.Is(appendErr, audit.ErrAlreadyExists) {
				return nil
			}
			return fmt.Errorf("events: evidence_recorded append: %w", appendErr)
		}
		return nil
	})
}

// -----------------------------------------------------------------------------
// eventbus binding helpers — mirror the other governance subscribers so
// cmd/server/main.go wires this topic with the same shape.
// -----------------------------------------------------------------------------

// HandleEvidenceRecordedMessage dispatches one eventbus delivery. A handler
// error nacks so the bus redelivers (DLQ after MaxDeliver attempts).
func HandleEvidenceRecordedMessage(
	ctx context.Context,
	sub *EvidenceRecordedSubscriber,
	msg eventbus.Message,
) error {
	if sub == nil {
		return errors.New("events: EvidenceRecordedSubscriber is nil; cannot dispatch")
	}

	attrs := EvidenceRecordedAttrsFromEnvelope(msg.Envelope)
	return sub.HandleEvidenceRecorded(ctx, msg.Payload, attrs)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (s *EvidenceRecordedSubscriber) checkInitialised() error {
	if s == nil || s.repo == nil {
		return errors.New("events: EvidenceRecordedSubscriber not initialised")
	}
	return nil
}

// evidenceRecordedReason renders an auditor-readable one-line summary for
// audit_log.reason. The load-bearing full detail (source_event_type,
// additional_fields, recorded_at) lives in the After JSONB payload.
func evidenceRecordedReason(evidenceType, sourceEventType, dimension, lifecycle, policyRef string) string {
	parts := make([]string, 0, 5)
	parts = append(parts, "evidence "+evidenceType)
	if dimension != "" {
		parts = append(parts, "dimension="+dimension)
	}
	if lifecycle != "" {
		parts = append(parts, "stage="+lifecycle)
	}
	if sourceEventType != "" {
		parts = append(parts, "source="+sourceEventType)
	}
	if policyRef != "" {
		parts = append(parts, "policy="+policyRef)
	}
	return strings.Join(parts, "; ")
}
