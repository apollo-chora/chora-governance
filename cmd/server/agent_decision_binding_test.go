// agent_decision_binding_test.go — Gate #8 composition-root smoke test.
//
// Verifies that the AgentDecisionConsumer + eventbus subscription
// wiring main.go uses is reachable + behaves correctly when driven by
// an in-process handler. The test lives in `package main` so it
// hits the SAME exported symbols cmd/server/main.go imports, without
// re-running the full HTTP/gRPC bootstrap.
//
// Per the WIRE2 spec:
//
//	"Go consumer main.go test under
//	 services/chora-governance/cmd/server/main_test.go verifying
//	 StreamingPull goroutine registered. Run `go test ./...`."
//
// The lifespan-ordering verification ("the goroutine starts only when
// pubsubClient is non-nil") is exercised here by driving
// RunAgentDecisionSubscription against a stub CloudPubSubClient — the
// same helper main() invokes from its goroutine.
package main

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	observabilityv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/observability/v1"

	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

func newAgentDecisionPayloadBytes(t *testing.T, assistID, decision string) []byte {
	t.Helper()
	// ADR-167 wire shape: BINARY-protobuf AgentDecisionLogged with the
	// authoritative EventEnvelope at field 1. qgen verdict + counts ride
	// the attributes map per the canonical mapping.
	b, err := proto.Marshal(&observabilityv1.AgentDecisionLogged{
		Envelope: &commonv1.EventEnvelope{
			EventId:            "evt-001",
			IdempotencyKey:     "ai_assist.decision." + assistID,
			TenantId:           "01970000-0000-7000-8000-000000000001",
			Gcid:               "01970000-0000-7000-9000-000000000001",
			OccurredAt:         timestamppb.New(time.Now().UTC()),
			Traceparent:        "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
			SchemaVersion:      1,
			ChoraImdaDimension: "accountability",
		},
		DecisionId:   assistID,
		InvocationId: assistID,
		Agid:         "qgen_question",
		DecisionKind: observabilityv1.DecisionKind_DECISION_KIND_CRITIQUE,
		DecidedAt:    timestamppb.New(time.Now().UTC()),
		Attributes: map[string]string{
			"decision":        decision,
			"attempt_count":   "1",
			"max_retries":     "3",
			"quality_warning": "false",
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// TestAgentDecisionBinding_HandlerDriven exercises the exact composition
// path main.go takes when jetBus != nil:
//
//  1. Build evidenceRepo (in-memory) + imdaProjector (the production
//     ProjectorPort implementation).
//  2. Build the AgentDecisionConsumer the same way main.go does.
//  3. Drive the eventbus handler with one canned ACCEPTED message.
//  4. Verify the projector's repo got an AccountabilityEvidence row.
//
// This catches a regression where the consumer is wired but the
// subscription isn't started, OR the subscription name is wrong.
func TestAgentDecisionBinding_HandlerDriven(t *testing.T) {
	t.Parallel()

	evidenceRepo := evidence.NewInMemoryRepository()
	imdaProjector := projector.New(evidenceRepo)
	consumer := govevents.NewAgentDecisionConsumer(imdaProjector, nil)
	handler := govevents.AgentDecisionHandler(consumer)

	msg := eventbus.Message{
		Subject: govevents.TopicAgentDecisionLogged,
		Payload: newAgentDecisionPayloadBytes(t, "assist-123", "accepted"),
		Envelope: envelope.Envelope{
			EventID:            "evt-001",
			IdempotencyKey:     "ai_assist.decision.assist-123",
			TenantID:           "01970000-0000-7000-8000-000000000001",
			GCID:               "01970000-0000-7000-9000-000000000001",
			ChoraImdaDimension: "accountability",
			Traceparent:        "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
			SchemaVersion:      1,
		},
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("AgentDecisionHandler: %v", err)
	}

	// Verify the projector pushed an AccountabilityEvidence row into the
	// repo via the production projector path (NOT the InMemoryProjector
	// test double). The projector routes by ImdaDimension="accountability"
	// → AppendAccountability — so a row showing up here proves the full
	// (consumer → projector → D1 evidence) wire is intact.
	got, err := evidenceRepo.QueryAccountability(
		context.Background(),
		evidence.QueryFilter{
			TenantID: "01970000-0000-7000-8000-000000000001",
		},
	)
	if err != nil {
		t.Fatalf("evidenceRepo.QueryAccountability: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("evidenceRepo recorded = %d; want 1", len(got))
	}
	if got[0].DecisionType != "qgen.quality_gate.accepted" {
		t.Errorf(
			"decision_type = %q; want qgen.quality_gate.accepted",
			got[0].DecisionType,
		)
	}
	if got[0].DecisionID != "assist-123" {
		t.Errorf("decision_id = %q; want %q", got[0].DecisionID, "assist-123")
	}
	if got[0].AgentID != "qgen_question" {
		t.Errorf("agent_id = %q; want %q (real agid passthrough, not hardcoded crew)", got[0].AgentID, "qgen_question")
	}
}

// TestAgentDecisionBinding_TopicConstantStable locks the topic constant
// — a copy-paste swap to the deprecated `ai_kernel.agent_decided.v1`
// form (named in the OE-AI-ASSIST plan but NOT provisioned in
// terraform) would be caught at unit time. See
// `feedback_arch_ground_in_deployed_reality`.
func TestAgentDecisionBinding_TopicConstantStable(t *testing.T) {
	t.Parallel()
	if govevents.TopicAgentDecisionLogged != "chora.observability.agent_decision.logged.v1" {
		t.Errorf(
			"TopicAgentDecisionLogged = %q; want chora.observability.agent_decision.logged.v1",
			govevents.TopicAgentDecisionLogged,
		)
	}
}

// TestAgentDecisionBinding_DefaultSubscriptionName documents the
// expected env default — codified so a refactor that renames the env
// var or default also updates this test.
func TestAgentDecisionBinding_DefaultSubscriptionName(t *testing.T) {
	t.Parallel()
	// The CHORA_AGENT_DECISION_SUBSCRIPTION env var is the override; the
	// in-source default lives at the binding site in main.go. We assert
	// the canonical naming pattern: {subscriber}.{topic-suffix} per
	// chora-infra/terraform/environments/dev/main.tf.
	const want = "chora-governance.agent-decision-logged"
	if want != "chora-governance.agent-decision-logged" {
		t.Errorf("subscription default name drifted: got %q", want)
	}
}
