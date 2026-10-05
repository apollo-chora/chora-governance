// Tests for the external-egress audit subscriber (CHO-2245).
//
// Subscribes to chora.governance.audit.external_egress.v1 emitted by
// chora-model-gateway (the single LLM chokepoint, ADR-231/220) for IMDA D2
// transparency + D1 accountability on every learner-triggered grounded web
// egress. Each message is a BINARY protobuf ExternalEgressAudited (envelope
// embedded as field 1) plus advisory outbox envelope attrs. The subscriber
// unmarshals, maps the AuditResult totally, and appends a hash-chained
// audit.Event row via the same audit.Repository port the payments-audit path
// uses (payments-audit parity).
//
// Per RED→GREEN convention these tests reference identifiers that do not yet
// exist in the source tree on first compile.
package events_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"
	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

const (
	egTestTenantID  = "01970000-0000-7000-8000-0000000000e1"
	egTestActorGCID = "01970000-0000-7000-8000-0000000000e2"
	egTestAuditID   = "01970000-0000-7000-8000-0000000000e3"
	egTestAgentID   = "familiar_seeker"
	egTestAction    = "familiar_far_sight_grounded_search"
	egTestTrace     = "00-abcdefabcdefabcdefabcdefabcdefab-abcdefabcdef0001-01"
)

// egressPayload builds a representative emitter-shaped ExternalEgressAudited
// with the envelope embedded as field 1 (the canonical envelope-complete
// pattern the gateway emits — see pg_grounded.go buildExternalEgressPayload).
func egressPayload(result governancev1.AuditResult) *governancev1.ExternalEgressAudited {
	return &governancev1.ExternalEgressAudited{
		Envelope: &commonv1.EventEnvelope{
			EventId:            egTestAuditID,
			IdempotencyKey:     egTestAuditID,
			TenantId:           egTestTenantID,
			Gcid:               egTestActorGCID,
			OccurredAt:         timestamppb.Now(),
			Traceparent:        egTestTrace,
			Tracestate:         "vendor=test",
			SourceService:      "chora-model-gateway",
			SchemaVersion:      1,
			ChoraImdaDimension: "transparency",
		},
		AuditId:               egTestAuditID,
		ActorGcid:             egTestActorGCID,
		AgentId:               egTestAgentID,
		ActionCode:            egTestAction,
		DirectiveHash:         "sha256:deadbeef",
		WebSearchQueries:      []string{"who ratified the montreal protocol"},
		CitationCount:         3,
		Result:                result,
		ModelArmorVerdictPre:  "ALLOW",
		ModelArmorVerdictPost: "ALLOW",
		Vendor:                "vertex_ai_gemini",
		ModelVersion:          "gemini-2.5-flash",
		OccurredAt:            timestamppb.Now(),
	}
}

func egressAttrs() events.AuditEgressEnvelopeAttrs {
	return events.AuditEgressEnvelopeAttrs{
		EventID:        egTestAuditID,
		IdempotencyKey: egTestAuditID,
		TenantID:       egTestTenantID,
		GCID:           egTestActorGCID,
		Traceparent:    egTestTrace,
		Tracestate:     "vendor=test",
		SchemaVersion:  "1",
	}
}

// -----------------------------------------------------------------------------
// Result → Decision mapping (must be TOTAL over the AuditResult enum)
// -----------------------------------------------------------------------------

func TestAuditEgressSubscriber_Allowed_HappyPath(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditEgressSubscriber(repo, nil)

	payload := egressPayload(governancev1.AuditResult_AUDIT_RESULT_ALLOWED)
	if err := sub.HandleExternalEgressAudited(
		context.Background(), mustMarshal(t, payload), egressAttrs(),
	); err != nil {
		t.Fatalf("handle: %v", err)
	}

	rows, err := repo.Query(context.Background(), audit.QueryFilter{TenantID: egTestTenantID})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row; got %d", len(rows))
	}
	got := rows[0]
	if got.Action != events.ActionExternalEgress {
		t.Errorf("Action = %q; want %q", got.Action, events.ActionExternalEgress)
	}
	if got.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted", got.Decision)
	}
	if got.SubjectType != "agent" {
		t.Errorf("SubjectType = %q; want agent", got.SubjectType)
	}
	if got.SubjectID != egTestAgentID {
		t.Errorf("SubjectID = %q; want agent_id %q", got.SubjectID, egTestAgentID)
	}
	if got.ActorGcid != egTestActorGCID {
		t.Errorf("ActorGcid = %q; want %q", got.ActorGcid, egTestActorGCID)
	}
	if got.Traceparent != egTestTrace {
		t.Errorf("Traceparent = %q; want %q", got.Traceparent, egTestTrace)
	}
	// The full proto payload must be preserved as auditor-readable JSON.
	if got.After == "" {
		t.Fatalf("After (JSON payload) should be populated, got empty")
	}
	if !strings.Contains(got.After, egTestAgentID) {
		t.Errorf("After payload missing agent_id: %s", got.After)
	}
	if !strings.Contains(strings.ToLower(got.Reason), "allowed") {
		t.Errorf("Reason should describe the allowed result; got %q", got.Reason)
	}
}

func TestAuditEgressSubscriber_Denied_MapsToDenied(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditEgressSubscriber(repo, nil)

	payload := egressPayload(governancev1.AuditResult_AUDIT_RESULT_DENIED)
	payload.DenialReason = "model_armor_pre_block"
	payload.CitationCount = 0
	payload.ModelArmorVerdictPre = "BLOCK"
	payload.ModelArmorVerdictPost = ""

	if err := sub.HandleExternalEgressAudited(
		context.Background(), mustMarshal(t, payload), egressAttrs(),
	); err != nil {
		t.Fatalf("handle: %v", err)
	}

	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: egTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row; got %d", len(rows))
	}
	got := rows[0]
	if got.Decision != audit.DecisionDenied {
		t.Errorf("Decision = %q; want denied", got.Decision)
	}
	if !strings.Contains(got.Reason, "model_armor_pre_block") {
		t.Errorf("Reason should carry the denial_reason; got %q", got.Reason)
	}
}

// ANOMALY is "allowed but flagged" — the egress DID dispatch, so on the binary
// audit Decision it maps to Permitted, with the anomaly surfaced in the reason
// (and the raw AUDIT_RESULT_ANOMALY preserved in the After payload).
func TestAuditEgressSubscriber_Anomaly_MapsToPermittedFlagged(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditEgressSubscriber(repo, nil)

	payload := egressPayload(governancev1.AuditResult_AUDIT_RESULT_ANOMALY)
	payload.DenialReason = "zero_citations"
	payload.CitationCount = 0

	if err := sub.HandleExternalEgressAudited(
		context.Background(), mustMarshal(t, payload), egressAttrs(),
	); err != nil {
		t.Fatalf("handle: %v", err)
	}

	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: egTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row; got %d", len(rows))
	}
	got := rows[0]
	if got.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted (allowed-but-flagged)", got.Decision)
	}
	if !strings.Contains(strings.ToLower(got.Reason), "anomaly") {
		t.Errorf("Reason should flag the anomaly; got %q", got.Reason)
	}
	if !strings.Contains(got.After, "AUDIT_RESULT_ANOMALY") {
		t.Errorf("After payload should preserve the raw ANOMALY result; got %s", got.After)
	}
}

func TestAuditEgressSubscriber_IdempotentReplay(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditEgressSubscriber(repo, nil)

	body := mustMarshal(t, egressPayload(governancev1.AuditResult_AUDIT_RESULT_ALLOWED))
	if err := sub.HandleExternalEgressAudited(context.Background(), body, egressAttrs()); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if err := sub.HandleExternalEgressAudited(context.Background(), body, egressAttrs()); err != nil {
		t.Fatalf("replay should be a no-op: %v", err)
	}
	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: egTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row after replay; got %d", len(rows))
	}
}

func TestAuditEgressSubscriber_MalformedPayload_Nacks(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditEgressSubscriber(repo, nil)

	// Not a valid protobuf ExternalEgressAudited.
	err := sub.HandleExternalEgressAudited(context.Background(), []byte("not-a-proto"), egressAttrs())
	if err == nil {
		t.Fatalf("expected decode error for malformed payload")
	}
	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: egTestTenantID})
	if len(rows) != 0 {
		t.Fatalf("malformed payload must append nothing; got %d rows", len(rows))
	}
}

// The AuditResult map must be TOTAL: the zero-value UNSPECIFIED sentinel and
// any out-of-contract enum value are explicit errors (NACK), never a silent
// default decision.
func TestAuditEgressSubscriber_UnknownResult_Errors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result governancev1.AuditResult
	}{
		{"unspecified-zero-value", governancev1.AuditResult_AUDIT_RESULT_UNSPECIFIED},
		{"out-of-contract", governancev1.AuditResult(99)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := audit.NewInMemoryRepository()
			sub := events.NewAuditEgressSubscriber(repo, nil)
			err := sub.HandleExternalEgressAudited(
				context.Background(), mustMarshal(t, egressPayload(c.result)), egressAttrs(),
			)
			if err == nil {
				t.Fatalf("expected error for %s result; got nil", c.name)
			}
			rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: egTestTenantID})
			if len(rows) != 0 {
				t.Fatalf("unknown result must append nothing; got %d rows", len(rows))
			}
		})
	}
}

func TestAuditEgressSubscriber_MissingTenant_Errors(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditEgressSubscriber(repo, nil)

	payload := egressPayload(governancev1.AuditResult_AUDIT_RESULT_ALLOWED)
	payload.Envelope.TenantId = ""
	attrs := egressAttrs()
	attrs.TenantID = "" // no fallback either

	err := sub.HandleExternalEgressAudited(context.Background(), mustMarshal(t, payload), attrs)
	if err == nil {
		t.Fatalf("expected envelope-validation error when tenant_id is absent everywhere")
	}
}

// -----------------------------------------------------------------------------
// eventbus dispatch — nil on success, error on failure
// -----------------------------------------------------------------------------

func TestAuditEgressHandler_Success(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditEgressSubscriber(repo, nil)
	handler := events.AuditEgressHandler(sub)

	msg := eventbus.Message{
		Payload: mustMarshal(t, egressPayload(governancev1.AuditResult_AUDIT_RESULT_ALLOWED)),
		Envelope: envelope.Envelope{
			EventID:  egTestAuditID,
			TenantID: egTestTenantID,
			GCID:     egTestActorGCID,
		},
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

func TestAuditEgressHandler_ErrorContract(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewAuditEgressSubscriber(repo, nil)
	handler := events.AuditEgressHandler(sub)

	if err := handler(context.Background(), eventbus.Message{Payload: []byte("garbage")}); err == nil {
		t.Fatal("expected dispatch error on malformed payload")
	}
	if err := (events.AuditEgressHandler(nil))(context.Background(), eventbus.Message{}); err == nil {
		t.Fatal("expected error for nil subscriber")
	}
}

func TestAuditEgressSubscriber_TopicConstant(t *testing.T) {
	t.Parallel()
	if events.TopicExternalEgressAudited != "chora.governance.audit.external_egress.v1" {
		t.Errorf("topic = %q; want chora.governance.audit.external_egress.v1", events.TopicExternalEgressAudited)
	}
}
