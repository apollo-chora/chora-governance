package events

import (
	"context"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// The consumer emitting a well-shaped IncomingEvent is only half the claim. This
// drives the REAL projector over the REAL evidence aggregate so the whole chain
// is proven: gateway proto bytes -> D3 route -> a policy_violation_log row.
// Without this the consumer could emit a perfectly-formed event that routeD3
// refuses, and every unit test above would still be green.
func TestPolicyViolation_EndToEndThroughRealProjector(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	c := NewPolicyViolationConsumer(projector.New(repo), nil)

	if err := c.Handle(context.Background(), violationBody(t, nil), PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	rows, err := repo.QueryPolicyViolations(context.Background(), evidence.QueryFilter{
		TenantID: "11111111-1111-7111-8111-000000000001",
	})
	if err != nil {
		t.Fatalf("QueryPolicyViolations: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("policy_violation_log rows = %d, want 1; the D3 route did not land", len(rows))
	}
	v := rows[0]
	if v.AgentID != "familiar_companion" {
		t.Errorf("agent_id = %q", v.AgentID)
	}
	if v.Detector != "MODEL_ARMOR" {
		t.Errorf("detector = %q", v.Detector)
	}
	if v.Severity != "high" {
		t.Errorf("severity = %q", v.Severity)
	}
	if !strings.Contains(v.PolicyName, "chora-guardrail-strict-dev") {
		t.Errorf("policy_name = %q, want the Armor template that fired", v.PolicyName)
	}
	if v.LifecycleStage != evidence.LifecycleRuntime {
		t.Errorf("lifecycle_stage = %q, want runtime", v.LifecycleStage)
	}
	if got, _ := v.Payload["verdict"].(string); got != "block" {
		t.Errorf("payload verdict = %q", got)
	}
}

// Re-delivery of the same event must not append a second evidence row even
// when a fresh consumer (empty in-memory inbox) handles it, because the
// evidence aggregate itself dedupes on event_id.
func TestPolicyViolation_EndToEndRedeliveryIsIdempotent(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	body := violationBody(t, nil)

	for i := 0; i < 2; i++ {
		c := NewPolicyViolationConsumer(projector.New(repo), nil)
		if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err != nil {
			t.Fatalf("Handle #%d: %v", i, err)
		}
	}

	rows, err := repo.QueryPolicyViolations(context.Background(), evidence.QueryFilter{
		TenantID: "11111111-1111-7111-8111-000000000001",
	})
	if err != nil {
		t.Fatalf("QueryPolicyViolations: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d after re-delivery across consumer restarts, want 1", len(rows))
	}
}
