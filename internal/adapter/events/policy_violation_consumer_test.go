package events

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"
)

// gatewayDescription reproduces chora-model-gateway's
// domain.PolicyViolationEvent.Description() byte for byte. The ratified proto
// carries no agent, leg or verdict field, so this key=value tail is the ONLY
// place the agent identity exists on the wire; if the producer's wording drifts
// these tests are what catches it.
func gatewayDescription(leg, agentID, invocationID, verdict string) string {
	return "Cloud Model Armor refused the call at the " + leg +
		" leg: agent_id=" + agentID +
		" invocation_id=" + invocationID +
		" verdict=" + verdict
}

func violationBody(t *testing.T, mutate func(*governancev1.PolicyViolationDetected)) []byte {
	t.Helper()
	detectedAt := time.Date(2026, 8, 14, 3, 21, 5, 0, time.UTC)
	msg := &governancev1.PolicyViolationDetected{
		Envelope: &commonv1.EventEnvelope{
			EventId:            "019ffbc0-625e-7edf-9037-578e1912a9fb",
			IdempotencyKey:     "019ffbc0-625e-7edf-9037-578e1912a9fb",
			TenantId:           "11111111-1111-7111-8111-000000000001",
			Gcid:               "22222222-2222-7222-8222-000000000002",
			OccurredAt:         timestamppb.New(detectedAt),
			Traceparent:        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			SourceService:      "chora-model-gateway",
			SchemaVersion:      1,
			ChoraImdaDimension: "safety_and_robustness",
			ImdaLifecycleStage: "runtime",
		},
		ViolationId:       "019ffbc0-625e-7edf-9037-578e1912a9fb",
		PolicyId:          "projects/chora-489812/locations/asia-southeast1/templates/chora-guardrail-strict-dev",
		PolicyKind:        governancev1.PolicyKind_POLICY_KIND_AI_USAGE,
		ViolationSeverity: governancev1.ViolationSeverity_VIOLATION_SEVERITY_HIGH,
		SubjectGcid:       "22222222-2222-7222-8222-000000000002",
		ResourceUri:       "chora.ai_kernel/invocation:019ffbc0-0000-7000-8000-000000000009",
		Description: gatewayDescription("PRE", "familiar_companion",
			"019ffbc0-0000-7000-8000-000000000009", "block"),
		Detector:   "MODEL_ARMOR",
		DetectedAt: timestamppb.New(detectedAt),
	}
	if mutate != nil {
		mutate(msg)
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// The acceptance-shaped test: a real gateway block must reach the projector as
// a D3 safety_and_robustness event whose EventType routes to
// policy_violation_log, carrying every field evidence.NewPolicyViolation
// requires non-blank.
func TestPolicyViolation_ProjectsD3Row(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)

	if err := c.Handle(context.Background(), violationBody(t, nil), PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	all := proj.all()
	if len(all) != 1 {
		t.Fatalf("rows = %d, want 1", len(all))
	}
	ev := all[0]

	if ev.ImdaDimension != "safety_and_robustness" {
		t.Errorf("imda_dimension = %q, want safety_and_robustness (ADR-141 D3)", ev.ImdaDimension)
	}
	if !strings.Contains(ev.EventType, "policy_violation") {
		t.Errorf("event_type %q would not route to policy_violation_log", ev.EventType)
	}
	if ev.LifecycleStage != "runtime" {
		t.Errorf("lifecycle_stage = %q, want runtime", ev.LifecycleStage)
	}
	if ev.EventID != "019ffbc0-625e-7edf-9037-578e1912a9fb" {
		t.Errorf("event_id = %q", ev.EventID)
	}
	if ev.TenantID != "11111111-1111-7111-8111-000000000001" {
		t.Errorf("tenant_id = %q; the RLS write is scoped on this", ev.TenantID)
	}
	// agent_id exists ONLY inside the description tail.
	if ev.AgentID != "familiar_companion" {
		t.Errorf("agent_id = %q, want familiar_companion parsed from the description tail", ev.AgentID)
	}
	if ev.PolicyName != "projects/chora-489812/locations/asia-southeast1/templates/chora-guardrail-strict-dev" {
		t.Errorf("policy_name = %q, want the Armor template that fired", ev.PolicyName)
	}
	if ev.Severity != "high" {
		t.Errorf("severity = %q, want high", ev.Severity)
	}
	if ev.Detector != "MODEL_ARMOR" {
		t.Errorf("detector = %q", ev.Detector)
	}
	if ev.Traceparent == "" {
		t.Error("traceparent dropped; the row cannot correlate with the refusing span")
	}
}

// The raw description must survive into the evidence payload verbatim: it is
// the only record of the leg, the invocation and the verdict, and an auditor
// must be able to re-read it even if the parse rules change later.
func TestPolicyViolation_PayloadCarriesRawFacts(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)

	if err := c.Handle(context.Background(), violationBody(t, nil), PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	p := proj.all()[0].Payload
	if p == nil {
		t.Fatal("payload nil; the leg/invocation/verdict facts are lost")
	}
	for _, k := range []string{"violation_id", "description", "resource_uri", "subject_gcid", "policy_kind", "leg", "invocation_id", "verdict", "source_service"} {
		if _, ok := p[k]; !ok {
			t.Errorf("payload missing %q", k)
		}
	}
	if got, _ := p["leg"].(string); got != "PRE" {
		t.Errorf("payload leg = %q, want PRE", got)
	}
	if got, _ := p["verdict"].(string); got != "block" {
		t.Errorf("payload verdict = %q, want block", got)
	}
	if got, _ := p["invocation_id"].(string); got != "019ffbc0-0000-7000-8000-000000000009" {
		t.Errorf("payload invocation_id = %q", got)
	}
	if got, _ := p["description"].(string); !strings.HasPrefix(got, "Cloud Model Armor refused") {
		t.Errorf("payload description = %q, want the verbatim producer description", got)
	}
}

// A POST-leg block is the other half of the producer's two hops.
func TestPolicyViolation_PostLegParsed(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)

	body := violationBody(t, func(m *governancev1.PolicyViolationDetected) {
		m.Description = gatewayDescription("POST", "oe_moderator", "inv-post-1", "block")
	})
	if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	ev := proj.all()[0]
	if ev.AgentID != "oe_moderator" {
		t.Errorf("agent_id = %q, want oe_moderator", ev.AgentID)
	}
	if got, _ := ev.Payload["leg"].(string); got != "POST" {
		t.Errorf("leg = %q, want POST", got)
	}
}

// Severity is a TOTAL map. An unknown future enum value must NOT be coerced
// into a plausible string; it is a contract change and must fail loud.
func TestPolicyViolation_SeverityMapIsTotal(t *testing.T) {
	cases := map[governancev1.ViolationSeverity]string{
		governancev1.ViolationSeverity_VIOLATION_SEVERITY_UNSPECIFIED: "unspecified",
		governancev1.ViolationSeverity_VIOLATION_SEVERITY_INFO:        "info",
		governancev1.ViolationSeverity_VIOLATION_SEVERITY_LOW:         "low",
		governancev1.ViolationSeverity_VIOLATION_SEVERITY_MEDIUM:      "medium",
		governancev1.ViolationSeverity_VIOLATION_SEVERITY_HIGH:        "high",
		governancev1.ViolationSeverity_VIOLATION_SEVERITY_CRITICAL:    "critical",
	}
	for sev, want := range cases {
		proj := &capturingProjector{}
		c := NewPolicyViolationConsumer(proj, nil)
		body := violationBody(t, func(m *governancev1.PolicyViolationDetected) {
			m.ViolationSeverity = sev
			m.Envelope.EventId = "sev-" + want
			m.Envelope.IdempotencyKey = "sev-" + want
		})
		if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err != nil {
			t.Fatalf("Handle(%v): %v", sev, err)
		}
		if got := proj.all()[0].Severity; got != want {
			t.Errorf("severity(%v) = %q, want %q", sev, got, want)
		}
	}

	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)
	body := violationBody(t, func(m *governancev1.PolicyViolationDetected) {
		m.ViolationSeverity = governancev1.ViolationSeverity(99)
	})
	if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err == nil {
		t.Fatal("expected a loud error for an unmapped severity enum value")
	}
}

// Fields the row cannot be honest without must NACK rather than write a
// half-true evidence row. tenant_id in particular scopes the RLS write.
func TestPolicyViolation_RequiredFieldsFailLoud(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*governancev1.PolicyViolationDetected)
	}{
		{"no event_id", func(m *governancev1.PolicyViolationDetected) { m.Envelope.EventId = "" }},
		{"no tenant_id", func(m *governancev1.PolicyViolationDetected) { m.Envelope.TenantId = "" }},
		{"no detector", func(m *governancev1.PolicyViolationDetected) { m.Detector = "" }},
		{"no policy_id", func(m *governancev1.PolicyViolationDetected) { m.PolicyId = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proj := &capturingProjector{}
			c := NewPolicyViolationConsumer(proj, nil)
			if err := c.Handle(context.Background(), violationBody(t, tc.mutate), PolicyViolationAttrs{}); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if got := len(proj.all()); got != 0 {
				t.Fatalf("wrote %d rows on a refused message, want 0", got)
			}
		})
	}

	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)
	if err := c.Handle(context.Background(), []byte("\xff\xfegarbage"), PolicyViolationAttrs{}); err == nil {
		t.Fatal("expected a decode error on a non-proto body")
	}
}

// The envelope is authoritative; Pub/Sub attributes are the fallback only.
func TestPolicyViolation_AttrsAreFallbackOnly(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)

	body := violationBody(t, func(m *governancev1.PolicyViolationDetected) {
		m.Envelope.EventId = ""
		m.Envelope.TenantId = ""
	})
	attrs := PolicyViolationAttrs{
		EventID:        "attr-event-id",
		IdempotencyKey: "attr-idem",
		TenantID:       "33333333-3333-7333-8333-000000000003",
	}
	if err := c.Handle(context.Background(), body, attrs); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	ev := proj.all()[0]
	if ev.EventID != "attr-event-id" || ev.TenantID != "33333333-3333-7333-8333-000000000003" {
		t.Errorf("attrs fallback not applied: %q / %q", ev.EventID, ev.TenantID)
	}

	// ...but the envelope WINS when both are present.
	proj2 := &capturingProjector{}
	c2 := NewPolicyViolationConsumer(proj2, nil)
	if err := c2.Handle(context.Background(), violationBody(t, nil), attrs); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := proj2.all()[0].TenantID; got != "11111111-1111-7111-8111-000000000001" {
		t.Errorf("tenant_id = %q; the proto envelope must win over attributes", got)
	}
}

// A producer whose description tail drifts must NOT silently drop the
// violation: the evidence keeps flowing under an explicit unattributed marker
// and the verbatim description still rides in the payload.
func TestPolicyViolation_UnparseableDescriptionStaysEvidence(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)

	body := violationBody(t, func(m *governancev1.PolicyViolationDetected) {
		m.Description = "a human moderator reported this post"
	})
	if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	all := proj.all()
	if len(all) != 1 {
		t.Fatalf("rows = %d, want the violation preserved as evidence", len(all))
	}
	if all[0].AgentID != AgentIDUnattributed {
		t.Errorf("agent_id = %q, want the explicit %q marker", all[0].AgentID, AgentIDUnattributed)
	}
	if got, _ := all[0].Payload["description"].(string); got != "a human moderator reported this post" {
		t.Errorf("payload description = %q, want verbatim", got)
	}
	if got, ok := all[0].Payload["agent_attribution"]; !ok || got != "absent" {
		t.Errorf("payload agent_attribution = %v, want an explicit absent marker", got)
	}
}

// At-least-once delivery must not double-write.
func TestPolicyViolation_Idempotent(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)
	body := violationBody(t, nil)
	if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err != nil {
		t.Fatalf("re-delivery: %v", err)
	}
	if got := len(proj.all()); got != 1 {
		t.Fatalf("re-delivery produced %d rows, want idempotent 1", got)
	}
}

func TestPolicyViolation_SubscribedTopic(t *testing.T) {
	c := NewPolicyViolationConsumer(&capturingProjector{}, nil)
	if got := c.SubscribedTopic(); got != TopicPolicyViolationDetected {
		t.Errorf("SubscribedTopic() = %q", got)
	}
	if TopicPolicyViolationDetected != "chora.governance.policy.violation_detected.v1" {
		t.Errorf("topic constant drifted: %q", TopicPolicyViolationDetected)
	}
}

func TestPolicyViolation_NilConsumerRefuses(t *testing.T) {
	var c *PolicyViolationConsumer
	if err := c.Handle(context.Background(), violationBody(t, nil), PolicyViolationAttrs{}); err == nil {
		t.Fatal("expected a nil-consumer error")
	}
}

// The evidence row must carry the instant Armor REFUSED the call, not the
// instant the consumer drained the backlog. This is the defect the G2
// acceptance surfaced: 54 violations spanning five days all projected with one
// timestamp, so the exported D3 CSV misdated every refusal.
func TestPolicyViolation_CarriesTheRefusalTimeNotIngestTime(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)

	if err := c.Handle(context.Background(), violationBody(t, nil), PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	want := time.Date(2026, 8, 14, 3, 21, 5, 0, time.UTC)
	got := proj.all()[0].OccurredAt
	if !got.Equal(want) {
		t.Errorf("OccurredAt = %s, want the proto's detected_at %s",
			got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

// A producer that omits detected_at must fall back to the envelope, and a
// producer that omits BOTH must leave the time unset so the domain stamps now.
// A nil timestamppb decodes to 1970 via AsTime(), which would silently backdate
// every evidence row by 56 years, so the zero case is the one that matters.
func TestPolicyViolation_MissingTimestampsDoNotBackdateTo1970(t *testing.T) {
	proj := &capturingProjector{}
	c := NewPolicyViolationConsumer(proj, nil)

	body := violationBody(t, func(m *governancev1.PolicyViolationDetected) {
		m.DetectedAt = nil
		m.Envelope.OccurredAt = nil
	})
	if err := c.Handle(context.Background(), body, PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	got := proj.all()[0].OccurredAt
	if !got.IsZero() {
		t.Errorf("OccurredAt = %s, want the ZERO time so the domain stamps now; a nil timestamppb must not become 1970",
			got.Format(time.RFC3339Nano))
	}

	// envelope-only: the envelope time is the fallback.
	proj2 := &capturingProjector{}
	c2 := NewPolicyViolationConsumer(proj2, nil)
	envOnly := violationBody(t, func(m *governancev1.PolicyViolationDetected) { m.DetectedAt = nil })
	if err := c2.Handle(context.Background(), envOnly, PolicyViolationAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := proj2.all()[0].OccurredAt; got.IsZero() {
		t.Error("envelope occurred_at was not used as the fallback")
	}
}
