// Tests for the H+ tx-history audit-payments subscribers.
//
// Subscribes to 3 chora.governance.audit.* topics emitted by chora-payments
// for IMDA D1 accountability on tenant-admin tx-history reads + cross-tenant
// PLATFORM_OPERATOR access + refund issuance:
//
//	chora.governance.audit.tenant_admin_viewed_payments.v1
//	chora.governance.audit.cross_tenant_payments_viewed.v1
//	chora.governance.audit.refund_issued.v1
//
// Wire shape: each message arrives as a protobuf-encoded payload (one of
// the 3 message types in chora-contracts/proto/events/governance/audit.proto)
// + the canonical envelope attrs (tenant_id, gcid, event_id, traceparent, ...).
// The subscriber unmarshals, validates, and appends an audit.Event aggregate
// row via the existing audit.Repository port — same hash-chain durability
// the gatekeeper-decision path uses.
//
// Per RED→GREEN convention these tests reference identifiers that do not yet
// exist in the source tree on first compile.
package events_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apollo-chora/chora-common/envelope"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

const (
	apTestTenantID     = "01970000-0000-7000-8000-0000000000a1"
	apTestActorGCID    = "01970000-0000-7000-8000-0000000000b1"
	apTestEventID      = "01970000-0000-7000-8000-0000000000c1"
	apTestIdempotency  = "tx-history:tenant-admin:01970000-0000-7000-8000-0000000000c1"
	apTestPurchaseID   = "01970000-0000-7000-8000-0000000000d1"
	apTestStripeRefund = "re_test_01H0000000000000000000"
	apTestTrace        = "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"
	apTestSecondTenant = "01970000-0000-7000-8000-0000000000a2"
	apTestThirdTenant  = "01970000-0000-7000-8000-0000000000a3"
)

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return b
}

func defaultAttrs() events.AuditPaymentsEnvelopeAttrs {
	return events.AuditPaymentsEnvelopeAttrs{
		EventID:        apTestEventID,
		IdempotencyKey: apTestIdempotency,
		TenantID:       apTestTenantID,
		GCID:           apTestActorGCID,
		Traceparent:    apTestTrace,
		Tracestate:     "vendor=test",
		SchemaVersion:  "1",
	}
}

// -----------------------------------------------------------------------------
// TenantAdminViewedPayments
// -----------------------------------------------------------------------------

func TestAuditPaymentsSubscriber_TenantAdminViewedPayments_HappyPath(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	payload := &governancev1.TenantAdminViewedPayments{
		EventId:    apTestEventID,
		TenantId:   apTestTenantID,
		ActorGcid:  apTestActorGCID,
		ActorRole:  "TENANT_ADMIN",
		OccurredAt: timestamppb.Now(),
		FilterContext: &governancev1.PurchaseFilterContext{
			AggregateType: "course_purchase",
			State:         "captured",
		},
	}

	if err := sub.HandleTenantAdminViewedPayments(
		context.Background(), mustMarshal(t, payload), defaultAttrs(),
	); err != nil {
		t.Fatalf("handle: %v", err)
	}

	rows, err := repo.Query(context.Background(), audit.QueryFilter{TenantID: apTestTenantID})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row; got %d", len(rows))
	}
	got := rows[0]
	if got.Action != events.ActionTenantAdminViewedPayments {
		t.Errorf("Action = %q; want %q", got.Action, events.ActionTenantAdminViewedPayments)
	}
	if got.SubjectType != "payments" {
		t.Errorf("SubjectType = %q; want %q", got.SubjectType, "payments")
	}
	if got.SubjectID != apTestTenantID {
		t.Errorf("SubjectID = %q; want tenant_id %q", got.SubjectID, apTestTenantID)
	}
	if got.ActorGcid != apTestActorGCID {
		t.Errorf("ActorGcid = %q; want %q", got.ActorGcid, apTestActorGCID)
	}
	if got.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted", got.Decision)
	}
	if got.After == "" {
		t.Errorf("After (JSON payload) should be populated, got empty")
	}
	if !strings.Contains(got.After, "TENANT_ADMIN") {
		t.Errorf("After payload missing actor_role: %s", got.After)
	}
	if got.Traceparent != apTestTrace {
		t.Errorf("Traceparent = %q; want %q", got.Traceparent, apTestTrace)
	}
}

func TestAuditPaymentsSubscriber_TenantAdminViewedPayments_IdempotentReplay(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	payload := &governancev1.TenantAdminViewedPayments{
		EventId:    apTestEventID,
		TenantId:   apTestTenantID,
		ActorGcid:  apTestActorGCID,
		ActorRole:  "TENANT_ADMIN",
		OccurredAt: timestamppb.Now(),
	}
	body := mustMarshal(t, payload)

	if err := sub.HandleTenantAdminViewedPayments(
		context.Background(), body, defaultAttrs(),
	); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if err := sub.HandleTenantAdminViewedPayments(
		context.Background(), body, defaultAttrs(),
	); err != nil {
		t.Fatalf("replay should be no-op: %v", err)
	}

	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: apTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row after replay; got %d", len(rows))
	}
}

func TestAuditPaymentsSubscriber_TenantAdminViewedPayments_RejectsMissingEnvelope(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	// Per ADR-167 the proto body is the CANONICAL envelope source; attrs are
	// advisory routing copies the subscriber only falls back to. So each
	// "missing_X" case must omit the field from BOTH the body (canonical) and
	// the attrs (fallback) — otherwise the fallback would silently re-supply
	// it and the validation would not fire.
	tests := map[string]struct {
		payload *governancev1.TenantAdminViewedPayments
		attrs   events.AuditPaymentsEnvelopeAttrs
	}{
		"missing_event_id": {
			payload: &governancev1.TenantAdminViewedPayments{
				// EventId omitted from canonical body
				TenantId:   apTestTenantID,
				ActorGcid:  apTestActorGCID,
				ActorRole:  "TENANT_ADMIN",
				OccurredAt: timestamppb.Now(),
			},
			attrs: events.AuditPaymentsEnvelopeAttrs{TenantID: apTestTenantID, GCID: apTestActorGCID},
		},
		"missing_tenant_id": {
			payload: &governancev1.TenantAdminViewedPayments{
				EventId: apTestEventID,
				// TenantId omitted from canonical body
				ActorGcid:  apTestActorGCID,
				ActorRole:  "TENANT_ADMIN",
				OccurredAt: timestamppb.Now(),
			},
			attrs: events.AuditPaymentsEnvelopeAttrs{EventID: apTestEventID, GCID: apTestActorGCID},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := sub.HandleTenantAdminViewedPayments(
				context.Background(), mustMarshal(t, tc.payload), tc.attrs,
			)
			if err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
			if !strings.Contains(err.Error(), "required") {
				t.Fatalf("expected 'required' error for %s; got %v", name, err)
			}
		})
	}
}

func TestAuditPaymentsSubscriber_TenantAdminViewedPayments_RejectsMalformedProto(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	err := sub.HandleTenantAdminViewedPayments(
		context.Background(), []byte("not-a-valid-proto"), defaultAttrs(),
	)
	if err == nil {
		t.Fatalf("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("expected 'decode' in error; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// CrossTenantPaymentsViewed
// -----------------------------------------------------------------------------

func TestAuditPaymentsSubscriber_CrossTenantPaymentsViewed_HappyPath(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	payload := &governancev1.CrossTenantPaymentsViewed{
		EventId:    apTestEventID,
		ActorGcid:  apTestActorGCID,
		ActorRole:  "PLATFORM_OPERATOR",
		OccurredAt: timestamppb.Now(),
		FilterContext: &governancev1.PurchaseFilterContext{
			State: "captured",
		},
		TenantIdsInView: []string{apTestTenantID, apTestSecondTenant, apTestThirdTenant},
	}

	if err := sub.HandleCrossTenantPaymentsViewed(
		context.Background(), mustMarshal(t, payload), defaultAttrs(),
	); err != nil {
		t.Fatalf("handle: %v", err)
	}

	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: apTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row; got %d", len(rows))
	}
	got := rows[0]
	if got.Action != events.ActionCrossTenantPaymentsViewed {
		t.Errorf("Action = %q; want %q", got.Action, events.ActionCrossTenantPaymentsViewed)
	}
	if got.SubjectType != "payments" {
		t.Errorf("SubjectType = %q; want %q", got.SubjectType, "payments")
	}
	// Subject IDs are the deduped tenant_ids touched.
	if !strings.Contains(got.SubjectID, apTestTenantID) ||
		!strings.Contains(got.SubjectID, apTestSecondTenant) ||
		!strings.Contains(got.SubjectID, apTestThirdTenant) {
		t.Errorf("SubjectID should list tenant_ids in view; got %q", got.SubjectID)
	}
	if got.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted", got.Decision)
	}
	if !strings.Contains(got.After, "PLATFORM_OPERATOR") {
		t.Errorf("After payload missing actor_role: %s", got.After)
	}
}

func TestAuditPaymentsSubscriber_CrossTenantPaymentsViewed_RejectsNonPlatformOperator(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	payload := &governancev1.CrossTenantPaymentsViewed{
		EventId:    apTestEventID,
		ActorGcid:  apTestActorGCID,
		ActorRole:  "TENANT_ADMIN", // wrong role
		OccurredAt: timestamppb.Now(),
	}

	err := sub.HandleCrossTenantPaymentsViewed(
		context.Background(), mustMarshal(t, payload), defaultAttrs(),
	)
	if err == nil {
		t.Fatalf("expected role validation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "platform_operator") {
		t.Fatalf("expected platform_operator in error; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// RefundIssued
// -----------------------------------------------------------------------------

func TestAuditPaymentsSubscriber_RefundIssued_HappyPath(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	payload := &governancev1.RefundIssued{
		EventId:        apTestEventID,
		TenantId:       apTestTenantID,
		ActorGcid:      apTestActorGCID,
		ActorRole:      "TENANT_ADMIN",
		OccurredAt:     timestamppb.Now(),
		PurchaseId:     apTestPurchaseID,
		AggregateType:  "course_purchase",
		AmountCents:    9900,
		Currency:       "sgd",
		Reason:         "duplicate charge",
		StripeRefundId: apTestStripeRefund,
	}

	if err := sub.HandleRefundIssued(
		context.Background(), mustMarshal(t, payload), defaultAttrs(),
	); err != nil {
		t.Fatalf("handle: %v", err)
	}

	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: apTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row; got %d", len(rows))
	}
	got := rows[0]
	if got.Action != events.ActionRefundIssued {
		t.Errorf("Action = %q; want %q", got.Action, events.ActionRefundIssued)
	}
	if got.SubjectType != "purchase" {
		t.Errorf("SubjectType = %q; want %q", got.SubjectType, "purchase")
	}
	if got.SubjectID != apTestPurchaseID {
		t.Errorf("SubjectID = %q; want purchase_id %q", got.SubjectID, apTestPurchaseID)
	}
	if got.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted", got.Decision)
	}
	if !strings.Contains(got.After, apTestStripeRefund) {
		t.Errorf("After payload missing stripe_refund_id: %s", got.After)
	}
	if !strings.Contains(got.After, "9900") {
		t.Errorf("After payload missing amount_cents: %s", got.After)
	}
}

func TestAuditPaymentsSubscriber_RefundIssued_RejectsAuditorRole(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	payload := &governancev1.RefundIssued{
		EventId:        apTestEventID,
		TenantId:       apTestTenantID,
		ActorGcid:      apTestActorGCID,
		ActorRole:      "AUDITOR", // forbidden per proto comment line 207
		OccurredAt:     timestamppb.Now(),
		PurchaseId:     apTestPurchaseID,
		AggregateType:  "course_purchase",
		AmountCents:    9900,
		Currency:       "sgd",
		StripeRefundId: apTestStripeRefund,
	}

	err := sub.HandleRefundIssued(
		context.Background(), mustMarshal(t, payload), defaultAttrs(),
	)
	if err == nil {
		t.Fatalf("expected role validation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "auditor") {
		t.Fatalf("expected auditor rejection in error; got %v", err)
	}
}

func TestAuditPaymentsSubscriber_RefundIssued_IdempotentReplay(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	payload := &governancev1.RefundIssued{
		EventId:        apTestEventID,
		TenantId:       apTestTenantID,
		ActorGcid:      apTestActorGCID,
		ActorRole:      "TENANT_ADMIN",
		OccurredAt:     timestamppb.Now(),
		PurchaseId:     apTestPurchaseID,
		AggregateType:  "course_purchase",
		AmountCents:    9900,
		Currency:       "sgd",
		StripeRefundId: apTestStripeRefund,
	}
	body := mustMarshal(t, payload)

	if err := sub.HandleRefundIssued(context.Background(), body, defaultAttrs()); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if err := sub.HandleRefundIssued(context.Background(), body, defaultAttrs()); err != nil {
		t.Fatalf("replay should be no-op: %v", err)
	}

	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: apTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row after replay; got %d", len(rows))
	}
}

// -----------------------------------------------------------------------------
// Topic constants
// -----------------------------------------------------------------------------

func TestAuditPaymentsSubscriber_TopicConstants(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"tenant_admin_viewed_payments": events.TopicTenantAdminViewedPayments,
		"cross_tenant_payments_viewed": events.TopicCrossTenantPaymentsViewed,
		"refund_issued":                events.TopicRefundIssued,
	}
	expected := map[string]string{
		"tenant_admin_viewed_payments": "chora.governance.audit.tenant_admin_viewed_payments.v1",
		"cross_tenant_payments_viewed": "chora.governance.audit.cross_tenant_payments_viewed.v1",
		"refund_issued":                "chora.governance.audit.refund_issued.v1",
	}
	for k, v := range expected {
		if want[k] != v {
			t.Errorf("topic %s = %q; want %q", k, want[k], v)
		}
	}
}

// -----------------------------------------------------------------------------
// eventbus binding helpers (mirror agent_decision_subscriber_test pattern)
// -----------------------------------------------------------------------------

func TestAuditPaymentsAttrsFromEnvelope_AllFields(t *testing.T) {
	t.Parallel()

	attrs := events.AuditPaymentsAttrsFromEnvelope(envelope.Envelope{
		EventID:        apTestEventID,
		IdempotencyKey: apTestIdempotency,
		TenantID:       apTestTenantID,
		GCID:           apTestActorGCID,
		Traceparent:    apTestTrace,
		Tracestate:     "vendor=test",
		SchemaVersion:  1,
	})

	if attrs.EventID != apTestEventID {
		t.Errorf("EventID = %q; want %q", attrs.EventID, apTestEventID)
	}
	if attrs.TenantID != apTestTenantID {
		t.Errorf("TenantID = %q; want %q", attrs.TenantID, apTestTenantID)
	}
	if attrs.GCID != apTestActorGCID {
		t.Errorf("GCID = %q; want %q", attrs.GCID, apTestActorGCID)
	}
	if attrs.SchemaVersion != "1" {
		t.Errorf("SchemaVersion = %q; want %q", attrs.SchemaVersion, "1")
	}
}

func TestAuditPaymentsAttrsFromEnvelope_ZeroSafe(t *testing.T) {
	t.Parallel()
	attrs := events.AuditPaymentsAttrsFromEnvelope(envelope.Envelope{})
	if attrs.EventID != "" {
		t.Fatalf("zero envelope should yield zero attrs; got EventID=%q", attrs.EventID)
	}
}

// -----------------------------------------------------------------------------
// Repository failure surfaces (NACK path)
// -----------------------------------------------------------------------------

// stubAuditRepo lets us force an Append error.
type stubAuditRepo struct {
	audit.Repository
	appendErr error
}

func (s *stubAuditRepo) Append(_ context.Context, _ *audit.Event) error {
	return s.appendErr
}

func TestAuditPaymentsSubscriber_RepoFailureSurfaces(t *testing.T) {
	t.Parallel()
	repo := &stubAuditRepo{appendErr: errors.New("forced")}
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	payload := &governancev1.TenantAdminViewedPayments{
		EventId:    apTestEventID,
		TenantId:   apTestTenantID,
		ActorGcid:  apTestActorGCID,
		ActorRole:  "TENANT_ADMIN",
		OccurredAt: timestamppb.Now(),
	}

	err := sub.HandleTenantAdminViewedPayments(
		context.Background(), mustMarshal(t, payload), defaultAttrs(),
	)
	if err == nil {
		t.Fatalf("expected forced error to surface (NACK path)")
	}
	if !strings.Contains(err.Error(), "forced") {
		t.Fatalf("expected 'forced' in error; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// SubscribedTopics — exposes the 3 topics this subscriber binds to.
// -----------------------------------------------------------------------------

func TestAuditPaymentsSubscriber_SubscribedTopics(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditPaymentsSubscriber(repo, nil)

	got := sub.SubscribedTopics()
	if len(got) != 3 {
		t.Fatalf("expected 3 topics; got %d", len(got))
	}
	expected := map[string]bool{
		events.TopicTenantAdminViewedPayments: true,
		events.TopicCrossTenantPaymentsViewed: true,
		events.TopicRefundIssued:              true,
	}
	for _, topic := range got {
		if !expected[topic] {
			t.Errorf("unexpected topic %q", topic)
		}
	}
}
