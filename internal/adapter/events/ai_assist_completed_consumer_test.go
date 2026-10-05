package events

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	creationv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/creation/v1"

	"github.com/apollo-chora/chora-governance/internal/domain/projector"
)

// capturingProjector records the FULL IncomingEvent per Project call — the
// shared InMemoryProjector drops Audience/ExplanationMD, which the D2
// transparency fan-out needs to assert.
type capturingProjector struct {
	mu       sync.Mutex
	events   []projector.IncomingEvent
	failNext bool
}

func (p *capturingProjector) Project(_ context.Context, ev projector.IncomingEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext {
		p.failNext = false
		return context.Canceled
	}
	p.events = append(p.events, ev)
	return nil
}

func (p *capturingProjector) all() []projector.IncomingEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]projector.IncomingEvent, len(p.events))
	copy(out, p.events)
	return out
}

func (p *capturingProjector) byAudience(a string) []projector.IncomingEvent {
	out := []projector.IncomingEvent{}
	for _, ev := range p.all() {
		if ev.Audience == a {
			out = append(out, ev)
		}
	}
	return out
}

// completedBody builds a binary-encoded AiAssistCompleted with a realistic
// 4-option MCQ candidate (each option carrying a real explainer), a critic
// trace, and the envelope.
func completedBody(t *testing.T, assistID, eventID, tenant string, opts []map[string]any, criticNotes string, trace []map[string]any) []byte {
	t.Helper()
	cand := map[string]any{
		"stem":          "Which gas do plants primarily absorb during photosynthesis?",
		"question_type": "mcq",
		"options":       opts,
	}
	candJSON, _ := json.Marshal(cand)
	traceJSON, _ := json.Marshal(trace)
	msg := &creationv1.AiAssistCompleted{
		Envelope: &commonv1.EventEnvelope{
			EventId:            eventID,
			TenantId:           tenant,
			Gcid:               "author-gcid-1",
			Traceparent:        "00-trace-1-span-1-01",
			ChoraImdaDimension: "", // creation event leaves this blank; consumer stamps transparency
		},
		AssistId:             assistID,
		CandidatePayloadJson: string(candJSON),
		PipelineTraceJson:    string(traceJSON),
		CriticNotes:          criticNotes,
		QualityWarning:       false,
		AttemptCount:         1,
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func fourOptions() []map[string]any {
	return []map[string]any{
		{"option_id": "o1", "label": "Carbon dioxide", "is_correct": true, "explainer": "Plants fix CO2 into glucose in the Calvin cycle."},
		{"option_id": "o2", "label": "Oxygen", "is_correct": false, "explainer": "Oxygen is released, not absorbed, during photosynthesis."},
		{"option_id": "o3", "label": "Nitrogen", "is_correct": false, "explainer": "Nitrogen is inert to photosynthesis; fixation is microbial."},
		{"option_id": "o4", "label": "Hydrogen", "is_correct": false, "explainer": "Hydrogen comes from water splitting, not atmospheric uptake."},
	}
}

func TestAiAssistCompleted_FansOutThreeAudiences(t *testing.T) {
	proj := &capturingProjector{}
	c := NewAiAssistCompletedConsumer(proj, nil)

	body := completedBody(t, "11111111-1111-7111-8111-000000000001",
		"22222222-2222-7222-8222-000000000001", "demo-tenant",
		fourOptions(), "Distractors are plausible; correct option well-justified.",
		[]map[string]any{
			{"name": "generate", "status": "ok", "notes": "candidate generated"},
			{"name": "critique", "status": "accepted", "notes": "factually sound; options mutually exclusive"},
			{"name": "quality_gate", "status": "ACCEPTED", "notes": "critic accepted"},
		})

	if err := c.Handle(context.Background(), body, AiAssistCompletedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	all := proj.all()
	learner := proj.byAudience("learner")
	auditor := proj.byAudience("auditor")
	instructor := proj.byAudience("instructor_admin")

	if len(learner) != 4 {
		t.Fatalf("learner rows = %d, want 4", len(learner))
	}
	if len(auditor) != 1 {
		t.Fatalf("auditor rows = %d, want 1", len(auditor))
	}
	if len(instructor) != 1 {
		t.Fatalf("instructor_admin rows = %d, want 1", len(instructor))
	}
	if len(all) != 6 {
		t.Fatalf("total rows = %d, want 6", len(all))
	}

	// Every row: transparency dimension, non-blank explanation, distinct event_id.
	seen := map[string]bool{}
	for _, ev := range all {
		if ev.ImdaDimension != "transparency" {
			t.Errorf("row imda_dimension = %q, want transparency", ev.ImdaDimension)
		}
		if strings.TrimSpace(ev.ExplanationMD) == "" {
			t.Errorf("row %s has blank explanation_md", ev.Audience)
		}
		if strings.Contains(strings.ToLower(ev.EventType), "model_card") || strings.Contains(strings.ToLower(ev.EventType), "data_card") {
			t.Errorf("event_type %q would mis-route off decision_explanation", ev.EventType)
		}
		if seen[ev.EventID] {
			t.Errorf("duplicate event_id %s within one source event", ev.EventID)
		}
		seen[ev.EventID] = true
	}

	// Learner explanation text is the real option explainer (verbatim).
	wantExplainers := map[string]bool{
		"Plants fix CO2 into glucose in the Calvin cycle.":             true,
		"Oxygen is released, not absorbed, during photosynthesis.":     true,
		"Nitrogen is inert to photosynthesis; fixation is microbial.":  true,
		"Hydrogen comes from water splitting, not atmospheric uptake.": true,
	}
	for _, ev := range learner {
		if !wantExplainers[ev.ExplanationMD] {
			t.Errorf("learner explanation_md not a verbatim option explainer: %q", ev.ExplanationMD)
		}
		if !strings.HasPrefix(ev.DecisionID, "11111111-1111-7111-8111-000000000001") {
			t.Errorf("learner decision_id %q not derived from assist_id", ev.DecisionID)
		}
	}
	// Auditor explanation carries the real critic diagnosis.
	if !strings.Contains(auditor[0].ExplanationMD, "Distractors are plausible") {
		t.Errorf("auditor explanation missing critic_notes: %q", auditor[0].ExplanationMD)
	}
}

func TestAiAssistCompleted_MCQPayloadNesting(t *testing.T) {
	proj := &capturingProjector{}
	c := NewAiAssistCompletedConsumer(proj, nil)

	// options nested under mcq_payload (the alternate wire shape).
	cand := map[string]any{
		"stem":          "x",
		"question_type": "mcq",
		"mcq_payload":   map[string]any{"options": fourOptions()},
	}
	candJSON, _ := json.Marshal(cand)
	msg := &creationv1.AiAssistCompleted{
		Envelope:             &commonv1.EventEnvelope{EventId: "e2", TenantId: "demo"},
		AssistId:             "a2",
		CandidatePayloadJson: string(candJSON),
		CriticNotes:          "ok",
	}
	body, _ := proto.Marshal(msg)
	if err := c.Handle(context.Background(), body, AiAssistCompletedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := len(proj.byAudience("learner")); got != 4 {
		t.Fatalf("learner rows from mcq_payload nesting = %d, want 4", got)
	}
}

func TestAiAssistCompleted_SkipsEmptyExplainers(t *testing.T) {
	proj := &capturingProjector{}
	c := NewAiAssistCompletedConsumer(proj, nil)
	opts := []map[string]any{
		{"option_id": "o1", "label": "A", "explainer": "real rationale"},
		{"option_id": "o2", "label": "B", "explainer": ""},    // empty → skipped
		{"option_id": "o3", "label": "C", "explainer": "   "}, // blank → skipped
	}
	body := completedBody(t, "a3", "e3", "demo", opts, "", nil) // empty critic + nil trace
	if err := c.Handle(context.Background(), body, AiAssistCompletedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := len(proj.byAudience("learner")); got != 1 {
		t.Fatalf("learner rows = %d, want 1 (empty explainers skipped)", got)
	}
	// No critic_notes AND no trace → no auditor/instructor rows (no fabrication).
	if got := len(proj.byAudience("auditor")) + len(proj.byAudience("instructor_admin")); got != 0 {
		t.Fatalf("auditor/instructor rows = %d, want 0 when no critic reasoning exists", got)
	}
}

func TestAiAssistCompleted_Idempotent(t *testing.T) {
	proj := &capturingProjector{}
	c := NewAiAssistCompletedConsumer(proj, nil)
	body := completedBody(t, "a4", "e4-event", "demo", fourOptions(), "notes", nil)
	if err := c.Handle(context.Background(), body, AiAssistCompletedAttrs{}); err != nil {
		t.Fatalf("Handle 1: %v", err)
	}
	first := len(proj.all())
	// Re-delivery of the same event (same event_id) is skipped by the inbox.
	if err := c.Handle(context.Background(), body, AiAssistCompletedAttrs{}); err != nil {
		t.Fatalf("Handle 2: %v", err)
	}
	if got := len(proj.all()); got != first {
		t.Fatalf("re-delivery produced %d extra rows, want idempotent (0)", got-first)
	}
}

func TestAiAssistCompleted_DeterministicEventIDs(t *testing.T) {
	// Same source event → same derived row event_ids across consumer instances.
	body := completedBody(t, "a5", "e5-event", "demo", fourOptions(), "notes", nil)
	p1, p2 := &capturingProjector{}, &capturingProjector{}
	_ = NewAiAssistCompletedConsumer(p1, nil).Handle(context.Background(), body, AiAssistCompletedAttrs{})
	_ = NewAiAssistCompletedConsumer(p2, nil).Handle(context.Background(), body, AiAssistCompletedAttrs{})
	ids1, ids2 := map[string]bool{}, map[string]bool{}
	for _, ev := range p1.all() {
		ids1[ev.Audience+"|"+ev.EventID] = true
	}
	for _, ev := range p2.all() {
		ids2[ev.Audience+"|"+ev.EventID] = true
	}
	if len(ids1) != len(ids2) || len(ids1) == 0 {
		t.Fatalf("id sets differ in size: %d vs %d", len(ids1), len(ids2))
	}
	for k := range ids1 {
		if !ids2[k] {
			t.Fatalf("event_id not deterministic across instances: %s", k)
		}
	}
}

func TestAiAssistCompleted_Validation(t *testing.T) {
	proj := &capturingProjector{}
	c := NewAiAssistCompletedConsumer(proj, nil)
	// missing tenant_id
	msg := &creationv1.AiAssistCompleted{
		Envelope:             &commonv1.EventEnvelope{EventId: "e6"},
		AssistId:             "a6",
		CandidatePayloadJson: `{"options":[]}`,
	}
	body, _ := proto.Marshal(msg)
	if err := c.Handle(context.Background(), body, AiAssistCompletedAttrs{}); err == nil {
		t.Fatal("expected validation error for missing tenant_id")
	}
	// proto decode failure
	if err := c.Handle(context.Background(), []byte("not-a-proto-\xff\xfe"), AiAssistCompletedAttrs{}); err == nil {
		t.Fatal("expected decode error on garbage body")
	}
}

func TestAiAssistCompleted_HandleEnvelopeAndTopic(t *testing.T) {
	proj := &capturingProjector{}
	c := NewAiAssistCompletedConsumer(proj, nil)
	if c.SubscribedTopic() != TopicAiAssistCompleted {
		t.Fatalf("SubscribedTopic = %q", c.SubscribedTopic())
	}
	body := completedBody(t, "a7", "e7", "demo", fourOptions(), "notes", nil)
	if err := c.HandleEnvelope(context.Background(), body); err != nil {
		t.Fatalf("HandleEnvelope: %v", err)
	}
	if len(proj.byAudience("learner")) != 4 {
		t.Fatalf("HandleEnvelope did not project learner rows")
	}
}

func TestAiAssistCompleted_MalformedCandidateAndMarkers(t *testing.T) {
	// Malformed candidate JSON → no learner rows, but auditor/instructor still emit.
	proj := &capturingProjector{}
	c := NewAiAssistCompletedConsumer(proj, nil)
	msg := &creationv1.AiAssistCompleted{
		Envelope:             &commonv1.EventEnvelope{EventId: "e8", TenantId: "demo"},
		AssistId:             "a8",
		CandidatePayloadJson: `{not valid json`,
		CriticNotes:          "diagnosis present",
	}
	body, _ := proto.Marshal(msg)
	if err := c.Handle(context.Background(), body, AiAssistCompletedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := len(proj.byAudience("learner")); got != 0 {
		t.Fatalf("malformed candidate yielded %d learner rows, want 0", got)
	}
	if got := len(proj.byAudience("auditor")); got != 1 {
		t.Fatalf("auditor row from critic_notes missing")
	}
	// optionMarker overflow past Z.
	if m := optionMarker(26); m != "27" {
		t.Fatalf("optionMarker(26) = %q, want 27", m)
	}
	if m := optionMarker(2); m != "C" {
		t.Fatalf("optionMarker(2) = %q, want C", m)
	}
}
