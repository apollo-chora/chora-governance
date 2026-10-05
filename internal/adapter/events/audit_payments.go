// AuditPaymentsSubscriber routes the 3 new H+ tx-history audit topics
// from chora-payments into the chora-governance audit_log as append-only
// hash-chained entries — the IMDA D1 accountability evidence trail.
//
// Source-of-truth:
//   - chora-contracts/proto/events/governance/audit.proto (commit 8bb1b49b)
//     §TenantAdminViewedPayments / §CrossTenantPaymentsViewed / §RefundIssued
//   - .claude/rules/ddd-enforcement.md (audit aggregate, append-only)
//   - logical-growing-cat plan Phase 2 Agent A4
//
// Topics (all v1):
//
//	chora.governance.audit.tenant_admin_viewed_payments.v1
//	chora.governance.audit.cross_tenant_payments_viewed.v1
//	chora.governance.audit.refund_issued.v1
//
// Publisher side: chora-payments emits these via its outbox (Agent A1).
// Subscriber side: this file. Per [[feedback-d6-resilience-first-class]]
// Pillar 2: Handle returns error on failure so the caller's Pub/Sub
// adapter Nacks for redelivery (DLQ on max_delivery_attempts).
//
// Hexagonal: INBOUND adapter; depends only on the audit.Repository port.
// No cross-DB queries; chora_governance is the only DB this touches.
//
// Schema fit: audit_log (migration 0001_initial.sql) is event_kind-agnostic.
// The `action` column carries the discriminator (1 of 3 constants below),
// `subject_type` + `subject_id` index the audited resource, and the
// full proto payload is serialised as a JSON blob into `after_state`. No
// new migration / enum value needed — the existing audit aggregate
// accepts the 3 new kinds cleanly.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"
	"github.com/apollo-chora/chora-common/idempotent"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

// -----------------------------------------------------------------------------
// Topic constants (canonical names per the user spec + contracts proto).
// -----------------------------------------------------------------------------

const (
	TopicTenantAdminViewedPayments = "chora.governance.audit.tenant_admin_viewed_payments.v1"
	TopicCrossTenantPaymentsViewed = "chora.governance.audit.cross_tenant_payments_viewed.v1"
	TopicRefundIssued              = "chora.governance.audit.refund_issued.v1"
)

// -----------------------------------------------------------------------------
// Action discriminators stamped into audit_log.action. The audit aggregate's
// existing schema (VARCHAR(128) action) accepts these without extension.
// -----------------------------------------------------------------------------

const (
	ActionTenantAdminViewedPayments = "payments.tenant_admin.viewed"
	ActionCrossTenantPaymentsViewed = "payments.cross_tenant.viewed"
	ActionRefundIssued              = "payments.refund.issued"
)

// AuditPaymentsInboxTTL is the dedupe-key retention window. Matches the
// AgentDecisionInboxTTL / closure InboxTTL convention — 24h covers the
// Pub/Sub default 7d redelivery window reduced for typical end-to-end
// orchestrator → governance latency.
const AuditPaymentsInboxTTL = 24 * time.Hour

// -----------------------------------------------------------------------------
// AuditPaymentsEnvelopeAttrs — envelope-derived Pub/Sub message attributes
// the dispatcher copies off the outbox row. Per ADR-167 the proto body is the
// CANONICAL envelope source; these attributes are advisory routing copies the
// subscriber consults only as a fallback when a body field is blank. Matches
// the AgentDecisionEnvelopeAttrs / decodeAgentDecision firstNonBlank(body,
// attrs) precedence.
// -----------------------------------------------------------------------------
type AuditPaymentsEnvelopeAttrs struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	Traceparent    string
	Tracestate     string
	SchemaVersion  string
}

// AuditPaymentsAttrsFromEnvelope lifts the eventbus envelope into the typed
// AuditPaymentsEnvelopeAttrs shape. Missing fields yield zero values; the
// subscriber's validation rejects empty mandatory fields downstream so a
// broken envelope surfaces as a clear error rather than a silent insert.
//
// Same shape as EnvelopeAttrsFromEnvelope for AgentDecision.
func AuditPaymentsAttrsFromEnvelope(env envelope.Envelope) AuditPaymentsEnvelopeAttrs {
	return AuditPaymentsEnvelopeAttrs{
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
// AuditPaymentsSubscriber — single subscriber type with one Handle method
// per topic. The cmd/server wiring registers each Handle against its
// canonical subscription name.
// -----------------------------------------------------------------------------

// AuditPaymentsSubscriber appends audit_log entries for the 3 H+ tx-history
// audit topics. Depends only on the audit.Repository port (hexagonal).
type AuditPaymentsSubscriber struct {
	repo  audit.Repository
	inbox idempotent.Store
	ttl   time.Duration

	mu sync.Mutex
}

// NewAuditPaymentsSubscriber wires the audit repo + idempotency inbox.
// When inbox is nil, an in-memory store is allocated.
func NewAuditPaymentsSubscriber(repo audit.Repository, inbox idempotent.Store) *AuditPaymentsSubscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &AuditPaymentsSubscriber{
		repo:  repo,
		inbox: inbox,
		ttl:   AuditPaymentsInboxTTL,
	}
}

// SubscribedTopics returns the 3 canonical topics this subscriber binds to.
// Cmd/server uses this to log + register the per-topic subscriptions.
func (s *AuditPaymentsSubscriber) SubscribedTopics() []string {
	return []string{
		TopicTenantAdminViewedPayments,
		TopicCrossTenantPaymentsViewed,
		TopicRefundIssued,
	}
}

// -----------------------------------------------------------------------------
// HandleTenantAdminViewedPayments
//   - subscribes to chora.governance.audit.tenant_admin_viewed_payments.v1
//   - subject = (payments, tenant_id) — the tenant whose payment history was viewed
//
// -----------------------------------------------------------------------------
func (s *AuditPaymentsSubscriber) HandleTenantAdminViewedPayments(
	ctx context.Context,
	body []byte,
	attrs AuditPaymentsEnvelopeAttrs,
) error {
	if err := s.checkInitialised(); err != nil {
		return err
	}

	var payload governancev1.TenantAdminViewedPayments
	if err := proto.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("events: tenant_admin_viewed_payments decode: %w", err)
	}

	// Canonical source = proto body (ADR-167); attrs are advisory routing
	// copies preferred only as a fallback when the body field is blank.
	tenantID := firstNonBlank(payload.GetTenantId(), attrs.TenantID)
	actorGCID := firstNonBlank(payload.GetActorGcid(), attrs.GCID)
	eventID := firstNonBlank(payload.GetEventId(), attrs.EventID)

	if err := validateEnvelope(eventID, tenantID); err != nil {
		return err
	}
	if err := validateActorRole(payload.GetActorRole(), allowedTenantAdminRoles); err != nil {
		return err
	}

	dedupeKey := dedupeKeyFor(attrs, eventID)
	return s.inbox.Process(ctx, dedupeKey, s.ttl, func() error {
		payloadJSON, err := marshalProtoJSON(&payload)
		if err != nil {
			return err
		}
		ev, err := audit.New(audit.NewParams{
			TenantID:    tenantID,
			Gcid:        actorGCID, // subject == actor here (no separate subject GCID)
			Action:      ActionTenantAdminViewedPayments,
			Resource:    "payments.tx_history",
			Decision:    audit.DecisionPermitted,
			Reason:      describeFilter(payload.GetFilterContext()),
			SubjectType: "payments",
			SubjectID:   tenantID, // tenant whose history was viewed
			ActorGcid:   actorGCID,
			After:       payloadJSON,
			Traceparent: attrs.Traceparent,
			Tracestate:  attrs.Tracestate,
		})
		if err != nil {
			return fmt.Errorf("events: tenant_admin_viewed_payments audit.New: %w", err)
		}
		if appendErr := s.repo.Append(ctx, ev); appendErr != nil {
			// ErrAlreadyExists is a no-op — Pub/Sub replays land here when
			// the dedupe-key path is bypassed (different idempotency_key on
			// the same payload). Treat as success so the message is Acked.
			if errors.Is(appendErr, audit.ErrAlreadyExists) {
				return nil
			}
			return fmt.Errorf("events: tenant_admin_viewed_payments append: %w", appendErr)
		}
		return nil
	})
}

// -----------------------------------------------------------------------------
// HandleCrossTenantPaymentsViewed
//   - subscribes to chora.governance.audit.cross_tenant_payments_viewed.v1
//   - emitted IN ADDITION to TenantAdminViewedPayments when the actor holds
//     PLATFORM_OPERATOR and the response touched rows from > 1 tenant.
//   - subject_id = the deduped tenant_ids_in_view (CSV) — load-bearing
//     IMDA D1 evidence for cross-tenant access.
//
// Because the proto omits tenant_id (cross-tenant by definition), we rely
// on the envelope's tenant_id (the actor's "home" tenant under whose RLS
// the audit row lives).
// -----------------------------------------------------------------------------
func (s *AuditPaymentsSubscriber) HandleCrossTenantPaymentsViewed(
	ctx context.Context,
	body []byte,
	attrs AuditPaymentsEnvelopeAttrs,
) error {
	if err := s.checkInitialised(); err != nil {
		return err
	}

	var payload governancev1.CrossTenantPaymentsViewed
	if err := proto.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("events: cross_tenant_payments_viewed decode: %w", err)
	}

	// event_id + actor_gcid: canonical proto body first (ADR-167), attrs as
	// advisory fallback. tenant_id is the lone exception — this proto omits
	// it by design (cross-tenant), so the envelope attr is the only source
	// (the actor's "home" tenant under whose RLS the audit row lives).
	tenantID := strings.TrimSpace(attrs.TenantID)
	actorGCID := firstNonBlank(payload.GetActorGcid(), attrs.GCID)
	eventID := firstNonBlank(payload.GetEventId(), attrs.EventID)

	if err := validateEnvelope(eventID, tenantID); err != nil {
		return err
	}
	// PLATFORM_OPERATOR is the ONLY accepted role on this event (per proto
	// comment line 174: "Always PLATFORM_OPERATOR"). Reject any other role
	// loudly — would indicate a publisher bug.
	if err := validateActorRole(payload.GetActorRole(), []string{"PLATFORM_OPERATOR"}); err != nil {
		return err
	}

	dedupeKey := dedupeKeyFor(attrs, eventID)
	return s.inbox.Process(ctx, dedupeKey, s.ttl, func() error {
		payloadJSON, err := marshalProtoJSON(&payload)
		if err != nil {
			return err
		}
		// SubjectID column is VARCHAR(128); a UUID is 36 chars so 3 fit
		// comfortably (3*36 + 2 commas = 110). Cap at 3 here — the
		// load-bearing full list lives in the After JSONB payload.
		tenantsForSubject := payload.GetTenantIdsInView()
		if len(tenantsForSubject) > 3 {
			tenantsForSubject = tenantsForSubject[:3]
		}
		tenantsInView := strings.Join(tenantsForSubject, ",")
		ev, err := audit.New(audit.NewParams{
			TenantID:    tenantID,
			Gcid:        actorGCID,
			Action:      ActionCrossTenantPaymentsViewed,
			Resource:    "payments.tx_history",
			Decision:    audit.DecisionPermitted,
			Reason:      fmt.Sprintf("cross-tenant view; tenants_in_view=%d; %s", len(payload.GetTenantIdsInView()), describeFilter(payload.GetFilterContext())),
			SubjectType: "payments",
			SubjectID:   tenantsInView, // first 3 (full list in After JSONB)
			ActorGcid:   actorGCID,
			After:       payloadJSON,
			Traceparent: attrs.Traceparent,
			Tracestate:  attrs.Tracestate,
		})
		if err != nil {
			return fmt.Errorf("events: cross_tenant_payments_viewed audit.New: %w", err)
		}
		if appendErr := s.repo.Append(ctx, ev); appendErr != nil {
			if errors.Is(appendErr, audit.ErrAlreadyExists) {
				return nil
			}
			return fmt.Errorf("events: cross_tenant_payments_viewed append: %w", appendErr)
		}
		return nil
	})
}

// -----------------------------------------------------------------------------
// HandleRefundIssued
//   - subscribes to chora.governance.audit.refund_issued.v1
//   - subject = (purchase, purchase_id) — the refunded purchase aggregate
//   - role gate: AUDITOR is rejected (per proto comment line 207 — refund is
//     a privileged mutation; AUDITOR is read-only at the API layer).
//
// -----------------------------------------------------------------------------
func (s *AuditPaymentsSubscriber) HandleRefundIssued(
	ctx context.Context,
	body []byte,
	attrs AuditPaymentsEnvelopeAttrs,
) error {
	if err := s.checkInitialised(); err != nil {
		return err
	}

	var payload governancev1.RefundIssued
	if err := proto.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("events: refund_issued decode: %w", err)
	}

	// Canonical source = proto body (ADR-167); attrs are advisory routing
	// copies preferred only as a fallback when the body field is blank.
	tenantID := firstNonBlank(payload.GetTenantId(), attrs.TenantID)
	actorGCID := firstNonBlank(payload.GetActorGcid(), attrs.GCID)
	eventID := firstNonBlank(payload.GetEventId(), attrs.EventID)

	if err := validateEnvelope(eventID, tenantID); err != nil {
		return err
	}
	if err := validateActorRole(payload.GetActorRole(), allowedRefundRoles); err != nil {
		return err
	}
	if strings.TrimSpace(payload.GetPurchaseId()) == "" {
		return errors.New("events: refund_issued payload purchase_id required")
	}
	if strings.TrimSpace(payload.GetStripeRefundId()) == "" {
		return errors.New("events: refund_issued payload stripe_refund_id required")
	}

	dedupeKey := dedupeKeyFor(attrs, eventID)
	return s.inbox.Process(ctx, dedupeKey, s.ttl, func() error {
		payloadJSON, err := marshalProtoJSON(&payload)
		if err != nil {
			return err
		}
		reason := strings.TrimSpace(payload.GetReason())
		if reason == "" {
			reason = fmt.Sprintf(
				"refund issued: amount_cents=%d currency=%s stripe_refund_id=%s",
				payload.GetAmountCents(),
				strings.ToLower(payload.GetCurrency()),
				payload.GetStripeRefundId(),
			)
		}
		ev, err := audit.New(audit.NewParams{
			TenantID:    tenantID,
			Gcid:        actorGCID,
			Action:      ActionRefundIssued,
			Resource:    "payments.refund",
			Decision:    audit.DecisionPermitted,
			Reason:      reason,
			SubjectType: "purchase",
			SubjectID:   payload.GetPurchaseId(),
			ActorGcid:   actorGCID,
			After:       payloadJSON,
			Traceparent: attrs.Traceparent,
			Tracestate:  attrs.Tracestate,
		})
		if err != nil {
			return fmt.Errorf("events: refund_issued audit.New: %w", err)
		}
		if appendErr := s.repo.Append(ctx, ev); appendErr != nil {
			if errors.Is(appendErr, audit.ErrAlreadyExists) {
				return nil
			}
			return fmt.Errorf("events: refund_issued append: %w", appendErr)
		}
		return nil
	})
}

// -----------------------------------------------------------------------------
// eventbus binding helpers — mirror the other governance subscribers so
// cmd/server/main.go wires the 3 topics with the same shape.
// -----------------------------------------------------------------------------

// HandleAuditPaymentsMessage dispatches one eventbus delivery to the
// appropriate Handle method based on the canonical subject identified by the
// `subject` argument. A handler error nacks so the bus redelivers (DLQ
// after MaxDeliver attempts).
func HandleAuditPaymentsMessage(
	ctx context.Context,
	sub *AuditPaymentsSubscriber,
	subject string,
	msg eventbus.Message,
) error {
	if sub == nil {
		return errors.New("events: AuditPaymentsSubscriber is nil; cannot dispatch")
	}

	attrs := AuditPaymentsAttrsFromEnvelope(msg.Envelope)

	var err error
	switch subject {
	case TopicTenantAdminViewedPayments:
		err = sub.HandleTenantAdminViewedPayments(ctx, msg.Payload, attrs)
	case TopicCrossTenantPaymentsViewed:
		err = sub.HandleCrossTenantPaymentsViewed(ctx, msg.Payload, attrs)
	case TopicRefundIssued:
		err = sub.HandleRefundIssued(ctx, msg.Payload, attrs)
	default:
		err = fmt.Errorf("events: unknown audit-payments subject %q", subject)
	}
	return err
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// allowedTenantAdminRoles is the set of roles accepted on the
// tenant_admin_viewed_payments event (per proto comment line 147).
var allowedTenantAdminRoles = []string{"TENANT_ADMIN", "OWNER", "AUDITOR"}

// allowedRefundRoles is the set of roles accepted on the refund_issued
// event (per proto comment line 207: TENANT_ADMIN | OWNER | PLATFORM_OPERATOR;
// AUDITOR is explicitly rejected at the API layer with 403 — and so MUST
// be rejected here on the audit side).
var allowedRefundRoles = []string{"TENANT_ADMIN", "OWNER", "PLATFORM_OPERATOR"}

func (s *AuditPaymentsSubscriber) checkInitialised() error {
	if s == nil || s.repo == nil {
		return errors.New("events: AuditPaymentsSubscriber not initialised")
	}
	return nil
}

// validateEnvelope rejects empty mandatory envelope fields.
func validateEnvelope(eventID, tenantID string) error {
	if strings.TrimSpace(eventID) == "" {
		return errors.New("events: audit-payments envelope event_id required")
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("events: audit-payments envelope tenant_id required")
	}
	return nil
}

// validateActorRole rejects roles not in the allowed set.
func validateActorRole(actorRole string, allowed []string) error {
	role := strings.TrimSpace(actorRole)
	if role == "" {
		return errors.New("events: audit-payments payload actor_role required")
	}
	for _, ok := range allowed {
		if role == ok {
			return nil
		}
	}
	return fmt.Errorf(
		"events: audit-payments role %q not in allowed set %v",
		role, allowed,
	)
}

// dedupeKeyFor prefers the envelope idempotency_key (deterministic per
// publisher decision) and falls back to event_id.
func dedupeKeyFor(attrs AuditPaymentsEnvelopeAttrs, eventID string) string {
	if k := strings.TrimSpace(attrs.IdempotencyKey); k != "" {
		return k
	}
	return eventID
}

// marshalProtoJSON serialises the protobuf payload to JSON for storage in
// audit_log.after_state (JSONB). Uses protojson to preserve field names
// matching the proto schema (camelCase by default) which is the
// auditor-readable shape.
func marshalProtoJSON(m proto.Message) (string, error) {
	b, err := protojson.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("events: audit-payments protojson marshal: %w", err)
	}
	// Round-trip through encoding/json to normalise key order — keeps the
	// JSONB column diff-stable across replays (protojson does not order
	// keys deterministically).
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return string(b), nil // best-effort; storing raw protojson is fine
	}
	stable, err := json.Marshal(raw)
	if err != nil {
		return string(b), nil
	}
	return string(stable), nil
}

// describeFilter renders a PurchaseFilterContext as a short human-readable
// reason string for audit_log.reason. Empty when the filter is nil/empty.
func describeFilter(f *governancev1.PurchaseFilterContext) string {
	if f == nil {
		return "no filter"
	}
	parts := make([]string, 0, 4)
	if v := strings.TrimSpace(f.GetAggregateType()); v != "" {
		parts = append(parts, "aggregate_type="+v)
	}
	if v := strings.TrimSpace(f.GetState()); v != "" {
		parts = append(parts, "state="+v)
	}
	if t := f.GetFrom(); t != nil {
		parts = append(parts, "from="+t.AsTime().UTC().Format(time.RFC3339))
	}
	if t := f.GetTo(); t != nil {
		parts = append(parts, "to="+t.AsTime().UTC().Format(time.RFC3339))
	}
	if len(parts) == 0 {
		return "no filter"
	}
	return "filter: " + strings.Join(parts, " ")
}
