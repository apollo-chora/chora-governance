package events

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"
)

func biasBody(t *testing.T, eventID, tenant, runID, attr, testType string, score, threshold float64) []byte {
	t.Helper()
	msg := &governancev1.BiasTestCompleted{
		Envelope: &commonv1.EventEnvelope{
			EventId:            eventID,
			TenantId:           tenant,
			ChoraImdaDimension: "fairness_and_human_oversight",
		},
		RunId:              runID,
		AgentId:            "mcq_ai_assist_crew",
		ProtectedAttribute: attr,
		TestType:           testType,
		Score:              score,
		Threshold:          threshold,
		RawBiasScore:       1 - score,
		JudgeModel:         "gemini-2.5-flash",
		Reason:             "no demographic bias detected in the generated MCQ",
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestBiasTest_ProjectsFairnessRow(t *testing.T) {
	proj := &capturingProjector{}
	c := NewBiasTestConsumer(proj, nil)

	body := biasBody(t, "33333333-3333-7333-8333-000000000001", "demo-tenant",
		"run-1", "demographic", "deepeval_bias_gender", 0.9, 0.5)

	if err := c.Handle(context.Background(), body, BiasTestAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	all := proj.all()
	if len(all) != 1 {
		t.Fatalf("rows = %d, want 1", len(all))
	}
	ev := all[0]
	if ev.ImdaDimension != "fairness_and_human_oversight" {
		t.Errorf("imda_dimension = %q", ev.ImdaDimension)
	}
	if ev.RunID != "run-1" || ev.AgentID != "mcq_ai_assist_crew" {
		t.Errorf("run/agent = %q/%q", ev.RunID, ev.AgentID)
	}
	if ev.ProtectedAttribute != "demographic" || ev.TestType != "deepeval_bias_gender" {
		t.Errorf("attr/type = %q/%q", ev.ProtectedAttribute, ev.TestType)
	}
	if ev.Score != 0.9 || ev.Threshold != 0.5 {
		t.Errorf("score/threshold = %v/%v", ev.Score, ev.Threshold)
	}
	// EventType must route to the bias branch.
	if !contains(ev.EventType, "bias") {
		t.Errorf("event_type %q would not route to bias_test_runs", ev.EventType)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestBiasTest_Validation(t *testing.T) {
	proj := &capturingProjector{}
	c := NewBiasTestConsumer(proj, nil)
	// missing run_id
	msg := &governancev1.BiasTestCompleted{
		Envelope:           &commonv1.EventEnvelope{EventId: "e", TenantId: "t"},
		ProtectedAttribute: "demographic",
		TestType:           "deepeval_bias_age",
	}
	body, _ := proto.Marshal(msg)
	if err := c.Handle(context.Background(), body, BiasTestAttrs{}); err == nil {
		t.Fatal("expected error for missing run_id")
	}
	if err := c.Handle(context.Background(), []byte("\xff\xfegarbage"), BiasTestAttrs{}); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestBiasTest_Idempotent(t *testing.T) {
	proj := &capturingProjector{}
	c := NewBiasTestConsumer(proj, nil)
	body := biasBody(t, "ev-bias-idem", "demo", "run-2", "demographic", "deepeval_bias_race", 0.4, 0.5)
	_ = c.Handle(context.Background(), body, BiasTestAttrs{})
	_ = c.Handle(context.Background(), body, BiasTestAttrs{})
	if got := len(proj.all()); got != 1 {
		t.Fatalf("re-delivery produced %d rows, want idempotent 1", got)
	}
}
