package events

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	consumptionv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/consumption/v1"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"
)

// weaknessEdge builds one ExtractedGrowthEdge. When summary != "" it is folded
// into descriptor_json under the canonical "summary" key (the verbatim text the
// learner row lifts); confidence + strength are carried for the auditor row.
func weaknessEdge(label, key, summary string, conf, str float32) *consumptionv1.ExtractedGrowthEdge {
	desc := ""
	if summary != "" {
		d, _ := json.Marshal(map[string]any{"summary": summary})
		desc = string(d)
	}
	return &consumptionv1.ExtractedGrowthEdge{
		ConceptLabel:   label,
		ConceptKey:     key,
		Confidence:     conf,
		Strength:       str,
		DescriptorJson: desc,
	}
}

// analyzedBody binary-encodes a WeaknessAnalyzed event with the envelope + the
// real model attribution (model_used + token counts) + the extracted edges.
func analyzedBody(t *testing.T, uploadID, eventID, tenant, learnerGCID, modelUsed string, inTok, outTok int32, edges []*consumptionv1.ExtractedGrowthEdge) []byte {
	t.Helper()
	msg := &consumptionv1.WeaknessAnalyzed{
		Envelope: &commonv1.EventEnvelope{
			EventId:     eventID,
			TenantId:    tenant,
			Gcid:        learnerGCID,
			Traceparent: "00-tracew-spanw-01",
		},
		UploadId:         uploadID,
		TenantId:         tenant,
		LearnerGcid:      learnerGCID,
		Edges:            edges,
		ModelUsed:        modelUsed,
		InputTokenCount:  inTok,
		OutputTokenCount: outTok,
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func threeEdges() []*consumptionv1.ExtractedGrowthEdge {
	return []*consumptionv1.ExtractedGrowthEdge{
		weaknessEdge("causes of riverine flooding", "riverine-flood-causes", "Confuses flood causes with effects.", 0.92, 0.80),
		weaknessEdge("plate boundary types", "plate-boundary-types", "Mixes up convergent and divergent boundaries.", 0.81, 0.65),
		weaknessEdge("urban heat island", "urban-heat-island", "", 0.70, 0.50), // no summary → learner row falls back to concept_label
	}
}

func TestWeaknessAnalyzed_FansOutThreeAudiences(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)

	body := analyzedBody(t,
		"11111111-1111-7111-8111-000000000001",
		"22222222-2222-7222-8222-000000000001",
		"demo-tenant", "learner-gcid-1",
		"gemini-3-pro-preview", 1820, 410, threeEdges())

	if err := c.Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	all := proj.all()
	learner := proj.byAudience("learner")
	auditor := proj.byAudience("auditor")
	instructor := proj.byAudience("instructor_admin")

	if len(learner) != 3 {
		t.Fatalf("learner rows = %d, want 3", len(learner))
	}
	if len(auditor) != 1 {
		t.Fatalf("auditor rows = %d, want 1", len(auditor))
	}
	if len(instructor) != 1 {
		t.Fatalf("instructor_admin rows = %d, want 1", len(instructor))
	}
	if len(all) != 5 {
		t.Fatalf("total rows = %d, want 5", len(all))
	}

	// Every row: transparency dimension, non-blank explanation, distinct event_id,
	// owner gcid propagated, and an event_type that routes to decision_explanation.
	seen := map[string]bool{}
	for _, ev := range all {
		if ev.ImdaDimension != "transparency" {
			t.Errorf("row imda_dimension = %q, want transparency", ev.ImdaDimension)
		}
		if strings.TrimSpace(ev.ExplanationMD) == "" {
			t.Errorf("row %s has blank explanation_md", ev.Audience)
		}
		if ev.OwnerGcid != "learner-gcid-1" {
			t.Errorf("row %s owner_gcid = %q, want learner-gcid-1", ev.Audience, ev.OwnerGcid)
		}
		if strings.Contains(strings.ToLower(ev.EventType), "model_card") || strings.Contains(strings.ToLower(ev.EventType), "data_card") {
			t.Errorf("event_type %q would mis-route off decision_explanation", ev.EventType)
		}
		// Internal/auditor/learner framing is neutral — the learner-facing
		// "Growth Edge" branding lives in the FE, never in the governance record.
		if strings.Contains(strings.ToLower(ev.ExplanationMD), "growth edge") {
			t.Errorf("explanation must not carry FE 'Growth Edge' branding: %q", ev.ExplanationMD)
		}
		if seen[ev.EventID] {
			t.Errorf("duplicate event_id %s within one source event", ev.EventID)
		}
		seen[ev.EventID] = true
	}

	// Learner explanation = verbatim descriptor summary (else concept_label fallback).
	wantLearner := map[string]bool{
		"Confuses flood causes with effects.":           true,
		"Mixes up convergent and divergent boundaries.": true,
		"urban heat island":                             true, // fallback (no summary)
	}
	for _, ev := range learner {
		if !wantLearner[ev.ExplanationMD] {
			t.Errorf("learner explanation_md not verbatim summary/label: %q", ev.ExplanationMD)
		}
		if !strings.HasPrefix(ev.DecisionID, "11111111-1111-7111-8111-000000000001") {
			t.Errorf("learner decision_id %q not derived from upload_id", ev.DecisionID)
		}
	}

	// Auditor (= instructor) explanation carries model attribution + per-edge
	// confidences, in "weakness" framing.
	a := auditor[0].ExplanationMD
	for _, want := range []string{"gemini-3-pro-preview", "1820", "410", "causes of riverine flooding", "0.92"} {
		if !strings.Contains(a, want) {
			t.Errorf("auditor explanation missing %q:\n%s", want, a)
		}
	}
	if !strings.Contains(strings.ToLower(a), "weak") {
		t.Errorf("auditor explanation should use 'weakness' framing:\n%s", a)
	}
	if auditor[0].ExplanationMD != instructor[0].ExplanationMD {
		t.Errorf("auditor + instructor_admin should share the same real diagnosis text")
	}
	if auditor[0].DecisionID != "11111111-1111-7111-8111-000000000001" {
		t.Errorf("auditor decision_id = %q, want the upload_id", auditor[0].DecisionID)
	}
}

func TestWeaknessAnalyzed_EmptyEdgesStillRecordsAnalysisRan(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)

	// Empty edges is a valid SUCCESS (nothing weak detected) — but the analysis
	// really ran (real model_used + tokens), so the auditor/instructor
	// transparency rows still emit. No learner rows (no edges).
	body := analyzedBody(t, "u-empty", "e-empty", "demo", "learner-2",
		"gemini-3-pro-preview", 900, 30, nil)
	if err := c.Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := len(proj.byAudience("learner")); got != 0 {
		t.Fatalf("learner rows = %d, want 0 (no edges)", got)
	}
	if got := len(proj.byAudience("auditor")); got != 1 {
		t.Fatalf("auditor rows = %d, want 1 (analysis ran; real model attribution)", got)
	}
	if got := len(proj.byAudience("instructor_admin")); got != 1 {
		t.Fatalf("instructor_admin rows = %d, want 1", got)
	}
	a := proj.byAudience("auditor")[0].ExplanationMD
	if !strings.Contains(a, "gemini-3-pro-preview") {
		t.Errorf("auditor explanation missing model attribution:\n%s", a)
	}
	if !strings.Contains(strings.ToLower(a), "no weak concept") {
		t.Errorf("auditor explanation should note zero weaknesses surfaced:\n%s", a)
	}
}

func TestWeaknessAnalyzed_NoRealContentEmitsNothing(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)
	// No edges, no model, no tokens → nothing real to report → no rows
	// (fail-loud / no-fabrication: never write an empty explanation).
	body := analyzedBody(t, "u-x", "e-x", "demo", "learner-3", "", 0, 0, nil)
	if err := c.Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := len(proj.all()); got != 0 {
		t.Fatalf("rows = %d, want 0 (nothing real to report)", got)
	}
}

func TestWeaknessAnalyzed_SkipsBlankEdges(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)
	edges := []*consumptionv1.ExtractedGrowthEdge{
		weaknessEdge("real concept", "real", "real summary", 0.9, 0.7),
		weaknessEdge("", "", "", 0.5, 0.5),         // fully blank → skipped (no fabrication)
		weaknessEdge("   ", "  ", "   ", 0.4, 0.3), // whitespace-only → skipped
	}
	body := analyzedBody(t, "u4", "e4", "demo", "learner-4", "m", 1, 1, edges)
	if err := c.Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := len(proj.byAudience("learner")); got != 1 {
		t.Fatalf("learner rows = %d, want 1 (blank edges skipped)", got)
	}
}

func TestWeaknessAnalyzed_MalformedDescriptorFallsBackToLabel(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)
	bad := &consumptionv1.ExtractedGrowthEdge{
		ConceptLabel:   "kinematics",
		DescriptorJson: `{not valid json`,
		Confidence:     0.6,
		Strength:       0.5,
	}
	body := analyzedBody(t, "u5", "e5", "demo", "learner-5", "m", 1, 1,
		[]*consumptionv1.ExtractedGrowthEdge{bad})
	if err := c.Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	learner := proj.byAudience("learner")
	if len(learner) != 1 {
		t.Fatalf("learner rows = %d, want 1", len(learner))
	}
	if learner[0].ExplanationMD != "kinematics" {
		t.Errorf("malformed descriptor should fall back to concept_label, got %q", learner[0].ExplanationMD)
	}
}

func TestWeaknessAnalyzed_Idempotent(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)
	body := analyzedBody(t, "u6", "e6-event", "demo", "learner-6", "m", 10, 5, threeEdges())
	if err := c.Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle 1: %v", err)
	}
	first := len(proj.all())
	if err := c.Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle 2: %v", err)
	}
	if got := len(proj.all()); got != first {
		t.Fatalf("re-delivery produced %d extra rows, want idempotent (0)", got-first)
	}
}

func TestWeaknessAnalyzed_DeterministicEventIDs(t *testing.T) {
	body := analyzedBody(t, "u7", "e7-event", "demo", "learner-7", "m", 10, 5, threeEdges())
	p1, p2 := &capturingProjector{}, &capturingProjector{}
	if err := NewWeaknessAnalyzedConsumer(p1, nil).Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle p1: %v", err)
	}
	if err := NewWeaknessAnalyzedConsumer(p2, nil).Handle(context.Background(), body, WeaknessAnalyzedAttrs{}); err != nil {
		t.Fatalf("Handle p2: %v", err)
	}
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

func TestWeaknessAnalyzed_AttrsFallbackWhenEnvelopeBlank(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)
	// Envelope omitted entirely; the Pub/Sub attrs supply event_id + tenant_id.
	msg := &consumptionv1.WeaknessAnalyzed{
		UploadId:    "u8",
		LearnerGcid: "learner-8",
		ModelUsed:   "m",
		Edges:       []*consumptionv1.ExtractedGrowthEdge{weaknessEdge("x", "x", "sx", 0.5, 0.5)},
	}
	body, _ := proto.Marshal(msg)
	attrs := WeaknessAnalyzedAttrs{EventID: "attr-event-8", TenantID: "attr-tenant", Traceparent: "00-a-b-01"}
	if err := c.Handle(context.Background(), body, attrs); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	all := proj.all()
	if len(all) == 0 {
		t.Fatal("expected rows projected via attrs fallback")
	}
	for _, ev := range all {
		if ev.TenantID != "attr-tenant" {
			t.Errorf("tenant_id = %q, want attr-tenant (from attrs)", ev.TenantID)
		}
	}
}

func TestWeaknessAnalyzed_Validation(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)

	// missing tenant_id (no envelope tenant, no attr tenant)
	noTenant := &consumptionv1.WeaknessAnalyzed{
		Envelope: &commonv1.EventEnvelope{EventId: "e9"},
		UploadId: "u9",
	}
	b1, _ := proto.Marshal(noTenant)
	if err := c.Handle(context.Background(), b1, WeaknessAnalyzedAttrs{}); err == nil {
		t.Fatal("expected validation error for missing tenant_id")
	}

	// missing upload_id
	noUpload := &consumptionv1.WeaknessAnalyzed{
		Envelope: &commonv1.EventEnvelope{EventId: "e10", TenantId: "demo"},
	}
	b2, _ := proto.Marshal(noUpload)
	if err := c.Handle(context.Background(), b2, WeaknessAnalyzedAttrs{}); err == nil {
		t.Fatal("expected validation error for missing upload_id")
	}

	// proto decode failure (FAIL LOUD → NACK → DLQ)
	if err := c.Handle(context.Background(), []byte("not-a-proto-\xff\xfe"), WeaknessAnalyzedAttrs{}); err == nil {
		t.Fatal("expected decode error on garbage body")
	}
}

func TestWeaknessAnalyzed_HandleEnvelopeAndTopic(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)
	if c.SubscribedTopic() != TopicWeaknessAnalyzed {
		t.Fatalf("SubscribedTopic = %q", c.SubscribedTopic())
	}
	if TopicWeaknessAnalyzed != "chora.consumption.weakness.analyzed.v1" {
		t.Fatalf("TopicWeaknessAnalyzed = %q", TopicWeaknessAnalyzed)
	}
	body := analyzedBody(t, "u11", "e11", "demo", "learner-11", "m", 1, 1, threeEdges())
	if err := c.HandleEnvelope(context.Background(), body); err != nil {
		t.Fatalf("HandleEnvelope: %v", err)
	}
	if len(proj.byAudience("learner")) != 3 {
		t.Fatalf("HandleEnvelope did not project learner rows")
	}
}

func TestWeaknessAnalyzed_NilConsumerSafe(t *testing.T) {
	var c *WeaknessAnalyzedConsumer
	if err := c.Handle(context.Background(), nil, WeaknessAnalyzedAttrs{}); err == nil {
		t.Fatal("expected error on nil consumer")
	}
}

// ---- subscriber binding helpers ----

func TestWeaknessAnalyzedAttrsFromEnvelope(t *testing.T) {
	attrs := WeaknessAnalyzedAttrsFromEnvelope(envelope.Envelope{
		EventID: "e", IdempotencyKey: "ik", TenantID: "t", GCID: "g", Traceparent: "tp",
	})
	if attrs.EventID != "e" || attrs.IdempotencyKey != "ik" || attrs.TenantID != "t" || attrs.GCID != "g" || attrs.Traceparent != "tp" {
		t.Fatalf("attrs not lifted correctly: %+v", attrs)
	}
	if got := WeaknessAnalyzedAttrsFromEnvelope(envelope.Envelope{}); got != (WeaknessAnalyzedAttrs{}) {
		t.Fatalf("zero envelope should yield zero attrs, got %+v", got)
	}
}

func TestWeaknessAnalyzedHandler_Success(t *testing.T) {
	proj := &capturingProjector{}
	c := NewWeaknessAnalyzedConsumer(proj, nil)
	handler := WeaknessAnalyzedHandler(c)
	if err := handler(context.Background(), eventbus.Message{
		Payload: analyzedBody(t, "u12", "e12", "demo", "learner-12", "m", 1, 1, threeEdges()),
	}); err != nil {
		t.Fatalf("WeaknessAnalyzedHandler: %v", err)
	}
	if len(proj.all()) == 0 {
		t.Fatal("projector got 0 rows; want at least 1")
	}
}

func TestWeaknessAnalyzedHandler_ErrorContract(t *testing.T) {
	c := NewWeaknessAnalyzedConsumer(&capturingProjector{}, nil)
	handler := WeaknessAnalyzedHandler(c)
	if err := handler(context.Background(), eventbus.Message{Payload: []byte("garbage-\xff")}); err == nil {
		t.Fatal("expected error on bad payload")
	}
	if err := (WeaknessAnalyzedHandler(nil))(context.Background(), eventbus.Message{}); err == nil {
		t.Fatal("expected error on nil consumer")
	}
}

func TestLearnerEdgeText_NilEdge(t *testing.T) {
	if got := learnerEdgeText(nil); got != "" {
		t.Fatalf("learnerEdgeText(nil) = %q, want empty", got)
	}
}
