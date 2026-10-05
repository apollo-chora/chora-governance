// Coverage-fill tests for projector — exercises error branches to hit 85%.
package projector_test

import (
	"context"
	"testing"

	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

func TestProjector_NilProjector_Errors(t *testing.T) {
	var p *projector.Projector
	if err := p.Project(context.Background(), projector.IncomingEvent{}); err == nil {
		t.Error("nil projector must return error")
	}
}

func TestProjector_EmptyDimension_Errors(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:  "e1",
		TenantID: "t",
		// no ImdaDimension
	})
	if err == nil {
		t.Error("expected error on missing dimension")
	}
}

// D2 model card with missing required fields → constructor error
func TestProjector_D2ModelCardMissingFields(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "transparency",
		EventType:     "chora.ai_kernel.model_card_registered.v1",
		// ModelID + ModelVersion + CardMD missing
	})
	if err == nil {
		t.Error("expected error on missing model card fields")
	}
}

// D2 data card with missing required fields → constructor error
func TestProjector_D2DataCardMissingFields(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "transparency",
		EventType:     "chora.ai_kernel.data_card_registered.v1",
		// DatasetID + Version + Card missing
	})
	if err == nil {
		t.Error("expected error on missing data card fields")
	}
}

// D2 generic explanation w/ missing decision_id → constructor error
func TestProjector_D2DecisionExplanationMissingFields(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "transparency",
		EventType:     "chora.something.v1",
		// DecisionID + ExplanationMD missing
	})
	if err == nil {
		t.Error("expected error on missing explanation fields")
	}
}

// D3 unknown event_type
func TestProjector_D3UnknownEventType(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "safety_and_robustness",
		EventType:     "chora.something.unrelated.v1",
	})
	if err == nil {
		t.Error("expected error on D3 unknown event_type")
	}
}

// D3 red-team with missing fields → constructor error
func TestProjector_D3RedTeamMissingFields(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "safety_and_robustness",
		EventType:     "chora.ai_kernel.red_team_run_completed.v1",
		// RunID + AgentID + Verdict missing
	})
	if err == nil {
		t.Error("expected error")
	}
}

// D3 eval missing fields
func TestProjector_D3EvalMissingFields(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "safety_and_robustness",
		EventType:     "chora.ai_kernel.eval_run_completed.v1",
	})
	if err == nil {
		t.Error("expected error")
	}
}

// D3 cost anomaly missing fields
func TestProjector_D3CostMissingFields(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "safety_and_robustness",
		EventType:     "chora.observability.cost_anomaly_detected.v1",
	})
	if err == nil {
		t.Error("expected error")
	}
}

// D3 policy violation missing fields
func TestProjector_D3PolicyViolationMissingFields(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "safety_and_robustness",
		EventType:     "chora.governance.content_policy_violation.v1",
	})
	if err == nil {
		t.Error("expected error")
	}
}

// D4 unknown event_type
func TestProjector_D4UnknownEventType(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "fairness_and_human_oversight",
		EventType:     "chora.something.unrelated.v1",
	})
	if err == nil {
		t.Error("expected error on D4 unknown event_type")
	}
}

// D4 bias missing fields
func TestProjector_D4BiasMissingFields(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "fairness_and_human_oversight",
		EventType:     "chora.ai_kernel.bias_test_completed.v1",
	})
	if err == nil {
		t.Error("expected error")
	}
}

// D4 HITL with prohibited Level 3 autonomy → constructor rejects
func TestProjector_D4HITLLevel3Rejected(t *testing.T) {
	p, _ := newProjector()
	err := p.Project(context.Background(), projector.IncomingEvent{
		EventID:       "e1",
		TenantID:      "t",
		ImdaDimension: "fairness_and_human_oversight",
		EventType:     "chora.governance.hitl_decision_recorded.v1",
		DecisionID:    "d",
		RunID:         "r",
		OperatorGcid:  "o",
		HitlVerdict:   "approve",
		AutonomyLevel: "hitl_l3", // PROHIBITED per ADR-141
	})
	if err == nil {
		t.Error("Level 3 autonomy MUST be rejected per ADR-141")
	}
}
