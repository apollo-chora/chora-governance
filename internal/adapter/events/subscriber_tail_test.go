// subscriber_tail_test.go — internal tests for the eventbus subscriber
// binding functions + small accessors the external suite does not reach:
//
//   - AiAssistCompleted / BiasTest handler dispatch (attrs lift, error
//     contract, nil-consumer guard)
//   - AuditPayments Handle*Message dispatch
//   - ExternalEgress SubscribedTopic
//   - CostAnomaly / BiasTest / AiAssist SubscribedTopic accessors
//   - BiasTest + HITLRequested HandleEnvelope wrappers
//   - Closure BootstrapClosureSubscriber (+ loadPIIMap paths)
//
// Written as INTERNAL (package events) to reuse the completedBody() /
// biasBody() protobuf builders from the consumer tests.
package events

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// -----------------------------------------------------------------------------
// failing projector
// -----------------------------------------------------------------------------

// subTailFailProj fails every Project call.
type subTailFailProj struct{}

func (subTailFailProj) Project(context.Context, projector.IncomingEvent) error {
	return errors.New("projector boom")
}

// -----------------------------------------------------------------------------
// AiAssistCompleted subscriber
// -----------------------------------------------------------------------------

func TestSubTail_AiAssist_AttrsFromEnvelope(t *testing.T) {
	t.Parallel()
	if got := AiAssistCompletedAttrsFromEnvelope(envelope.Envelope{}); got != (AiAssistCompletedAttrs{}) {
		t.Errorf("zero envelope → %+v", got)
	}
	got := AiAssistCompletedAttrsFromEnvelope(envelope.Envelope{
		EventID: "e1", IdempotencyKey: "k1", TenantID: "t1", GCID: "g1", Traceparent: "tp",
	})
	want := AiAssistCompletedAttrs{EventID: "e1", IdempotencyKey: "k1", TenantID: "t1", GCID: "g1", Traceparent: "tp"}
	if got != want {
		t.Errorf("got %+v; want %+v", got, want)
	}
}

func TestSubTail_AiAssist_HandlerContract(t *testing.T) {
	t.Parallel()
	consumer := NewAiAssistCompletedConsumer(NewInMemoryProjector(), nil)
	if consumer.SubscribedTopic() != TopicAiAssistCompleted {
		t.Errorf("SubscribedTopic = %q", consumer.SubscribedTopic())
	}

	handler := AiAssistCompletedHandler(consumer)
	if err := handler(context.Background(), eventbus.Message{
		Payload: completedBody(t, "a1", "e1", "t1", fourOptions(), "notes", nil),
	}); err != nil {
		t.Fatalf("AiAssistCompletedHandler: %v", err)
	}

	// nil consumer → error
	if err := (AiAssistCompletedHandler(nil))(context.Background(), eventbus.Message{}); err == nil {
		t.Error("nil consumer should error")
	}

	// consumer error (bad proto) → error
	if err := handler(context.Background(), eventbus.Message{Payload: []byte("not-a-proto")}); err == nil {
		t.Error("bad proto should error")
	}
}

func TestSubTail_AiAssist_HandlerPropagatesProjectorError(t *testing.T) {
	t.Parallel()
	consumer := NewAiAssistCompletedConsumer(subTailFailProj{}, nil)
	err := (AiAssistCompletedHandler(consumer))(context.Background(), eventbus.Message{
		Payload: completedBody(t, "a3", "e3", "t3", fourOptions(), "", nil),
	})
	if err == nil {
		t.Error("projector error should propagate")
	}
}

// -----------------------------------------------------------------------------
// BiasTest subscriber
// -----------------------------------------------------------------------------

func TestSubTail_Bias_AttrsFromEnvelope(t *testing.T) {
	t.Parallel()
	if got := BiasTestAttrsFromEnvelope(envelope.Envelope{}); got != (BiasTestAttrs{}) {
		t.Errorf("zero envelope → %+v", got)
	}
	got := BiasTestAttrsFromEnvelope(envelope.Envelope{EventID: "e1", IdempotencyKey: "k", TenantID: "t"})
	want := BiasTestAttrs{EventID: "e1", IdempotencyKey: "k", TenantID: "t"}
	if got != want {
		t.Errorf("got %+v; want %+v", got, want)
	}
}

func TestSubTail_Bias_HandlerContract(t *testing.T) {
	t.Parallel()
	consumer := NewBiasTestConsumer(NewInMemoryProjector(), nil)
	if consumer.SubscribedTopic() != TopicBiasTestCompleted {
		t.Errorf("SubscribedTopic = %q", consumer.SubscribedTopic())
	}

	handler := BiasTestHandler(consumer)
	if err := handler(context.Background(), eventbus.Message{
		Payload: biasBody(t, "e1", "t1", "run-1", "demographic", "synthetic", 0.9, 0.5),
	}); err != nil {
		t.Fatalf("BiasTestHandler: %v", err)
	}

	if err := (BiasTestHandler(nil))(context.Background(), eventbus.Message{}); err == nil {
		t.Error("nil consumer should error")
	}
}

func TestSubTail_Bias_HandleEnvelope(t *testing.T) {
	t.Parallel()
	consumer := NewBiasTestConsumer(NewInMemoryProjector(), nil)
	if err := consumer.HandleEnvelope(context.Background(),
		biasBody(t, "e1", "t1", "run-1", "demographic", "synthetic", 0.9, 0.5)); err != nil {
		t.Fatalf("HandleEnvelope: %v", err)
	}
}

// -----------------------------------------------------------------------------
// AuditPayments subscriber
// -----------------------------------------------------------------------------

func TestSubTail_AuditPayments_HandleMessage_Dispatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := audit.NewInMemoryRepository()
	sub := NewAuditPaymentsSubscriber(repo, nil)

	appendPayload := func(msg proto.Message) []byte {
		b, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}
	env := envelope.Envelope{
		EventID: "evt-1", IdempotencyKey: "idem-1", TenantID: "t1", GCID: "g1",
	}

	// tenant-admin subject → success
	if err := HandleAuditPaymentsMessage(ctx, sub, TopicTenantAdminViewedPayments, eventbus.Message{
		Payload: appendPayload(&governancev1.TenantAdminViewedPayments{
			EventId: "evt-1", TenantId: "t1", ActorGcid: "g1", ActorRole: "TENANT_ADMIN",
			OccurredAt: timestamppb.Now(),
		}),
		Envelope: env,
	}); err != nil {
		t.Errorf("tenant-admin: %v", err)
	}

	// cross-tenant subject → success (platform operator)
	if err := HandleAuditPaymentsMessage(ctx, sub, TopicCrossTenantPaymentsViewed, eventbus.Message{
		Payload: appendPayload(&governancev1.CrossTenantPaymentsViewed{
			EventId: "evt-2", ActorGcid: "g1", ActorRole: "PLATFORM_OPERATOR",
			OccurredAt: timestamppb.Now(), TenantIdsInView: []string{"t1", "t2"},
		}),
		Envelope: env,
	}); err != nil {
		t.Errorf("cross-tenant: %v", err)
	}

	// refund subject → success
	if err := HandleAuditPaymentsMessage(ctx, sub, TopicRefundIssued, eventbus.Message{
		Payload: appendPayload(&governancev1.RefundIssued{
			EventId: "evt-3", TenantId: "t1", ActorGcid: "g1", ActorRole: "TENANT_ADMIN",
			OccurredAt: timestamppb.Now(), PurchaseId: "p1", AggregateType: "course_purchase",
			AmountCents: 9900, Currency: "sgd", StripeRefundId: "sr-1",
		}),
		Envelope: env,
	}); err != nil {
		t.Errorf("refund: %v", err)
	}

	// nil subscriber → error
	if err := HandleAuditPaymentsMessage(ctx, nil, TopicRefundIssued, eventbus.Message{}); err == nil {
		t.Error("nil sub should error")
	}

	// unknown subject → error
	if err := HandleAuditPaymentsMessage(ctx, sub, "chora.governance.unknown.v1", eventbus.Message{}); err == nil {
		t.Error("unknown subject should error")
	}
}

// -----------------------------------------------------------------------------
// ExternalEgress + CostAnomaly subscribers
// -----------------------------------------------------------------------------

func egressMsg() eventbus.Message {
	return eventbus.Message{Payload: protoBytes(&governancev1.ExternalEgressAudited{
		Envelope: &commonv1.EventEnvelope{
			EventId: "eg-1", IdempotencyKey: "eg-1", TenantId: "t1", Gcid: "g1",
			OccurredAt: timestamppb.Now(), SourceService: "chora-model-gateway", SchemaVersion: 1,
		},
		AuditId: "eg-1", ActorGcid: "g1", ActionCode: "model.gateway_question", Result: governancev1.AuditResult_AUDIT_RESULT_ALLOWED,
		OccurredAt: timestamppb.Now(),
	})}
}

func protoBytes(m proto.Message) []byte {
	b, _ := proto.Marshal(m)
	return b
}

func TestSubTail_AuditEgress_SubscribedTopic(t *testing.T) {
	t.Parallel()
	sub := NewAuditEgressSubscriber(audit.NewInMemoryRepository(), nil)
	if sub.SubscribedTopic() != TopicExternalEgressAudited {
		t.Errorf("SubscribedTopic = %q", sub.SubscribedTopic())
	}
}

func TestSubTail_CostAnomaly_SubscribedTopic(t *testing.T) {
	t.Parallel()
	sub := NewCostAnomalySubscriber(evidence.NewInMemoryRepository(), nil)
	if sub.SubscribedTopic() != TopicCostAnomalyDetected {
		t.Errorf("SubscribedTopic = %q", sub.SubscribedTopic())
	}
}

func TestSubTail_HITLRequested_HandleEnvelope(t *testing.T) {
	t.Parallel()
	consumer := NewHITLRequestedConsumer(NewInMemoryProjector(), nil)
	body := []byte(`{
		"event_id":"hitl-1",
		"tenant_id":"t1",
		"imda_dimension":"fairness_and_human_oversight",
		"event_type":"hitl_requested",
		"decision_id":"dec-1",
		"run_id":"run-1",
		"operator_gcid":"",
		"autonomy_level":"l1"
	}`)
	if err := consumer.HandleEnvelope(context.Background(), body); err != nil {
		t.Fatalf("HandleEnvelope: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Closure bootstrap
// -----------------------------------------------------------------------------

func writePIIMap(t *testing.T) string {
	t.Helper()
	yaml := `domain: chora_a2a
version: "1"
fields_to_tokenize:
  - table: agent_profiles
    columns:
      - {column: display_name, strategy: hash}
retention_days_by_jurisdiction:
  sg: 365
on_creator_closure:
  strategy: deactivate
  show_authorship_as: "chora_community"
`
	path := filepath.Join(t.TempDir(), "PII_Closure_Map.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestSubTail_Closure_Bootstrap(t *testing.T) {
	t.Parallel()
	path := writePIIMap(t)
	sub, err := BootstrapClosureSubscriber(path, NewInMemoryClosureRepo(), NewInMemoryClosurePublisher(), nil)
	if err != nil {
		t.Fatalf("BootstrapClosureSubscriber: %v", err)
	}
	if sub == nil {
		t.Fatal("nil subscriber on success")
	}

	// missing file → error
	if _, err := BootstrapClosureSubscriber(filepath.Join(t.TempDir(), "missing.yaml"),
		NewInMemoryClosureRepo(), NewInMemoryClosurePublisher(), nil); err == nil {
		t.Error("missing file should error")
	}

	// invalid YAML → error
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("not: [valid"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := BootstrapClosureSubscriber(bad, NewInMemoryClosureRepo(), NewInMemoryClosurePublisher(), nil); err == nil {
		t.Error("invalid yaml should error")
	}
}
