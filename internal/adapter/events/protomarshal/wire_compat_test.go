// wire_compat_test verifies the binary bytes emitted by MarshalPayload parse
// cleanly into the generated proto types from chora-contracts. This is the
// load-bearing assertion — if these tests pass, the schema registry
// will accept the bytes.
//
// All 9 governance topics with flat protos exist as generated bindings in
// chora-contracts/gen/go/chora/governance/v1, so we round-trip through
// proto.Unmarshal here.
package protomarshal_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/adapter/events/protomarshal"
)

func wireCompatEnvelope() protomarshal.Envelope {
	t0 := time.Date(2026, 5, 16, 9, 30, 0, 0, time.UTC)
	return protomarshal.Envelope{
		EventID:        "01971a90-0000-7000-8000-00000000fffe",
		IdempotencyKey: "idemp-wire-gov-1",
		TenantID:       "01970000-0000-7000-8000-000000000abc",
		GCID:           "01970000-0000-7000-8000-000000000def",
		OccurredAt:     t0,
		PublishedAt:    t0.Add(time.Millisecond),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		Tracestate:     "vendor=value",
		SourceProject:  "chora-489812",
		SourceService:  "chora-governance",
		SchemaVersion:  1,
	}
}

// assertEnvelopeRoundTrip checks the inlined envelope sub-message decoded
// faithfully back to the input fields.
func assertEnvelopeRoundTrip(t *testing.T, env protomarshal.Envelope, e interface {
	GetEventId() string
	GetTenantId() string
	GetGcid() string
	GetTraceparent() string
	GetSchemaVersion() int32
	GetSourceService() string
}) {
	t.Helper()
	if e.GetEventId() != env.EventID {
		t.Fatalf("envelope.event_id: got %q want %q", e.GetEventId(), env.EventID)
	}
	if e.GetTenantId() != env.TenantID {
		t.Fatalf("envelope.tenant_id: got %q want %q", e.GetTenantId(), env.TenantID)
	}
	if e.GetGcid() != env.GCID {
		t.Fatalf("envelope.gcid: got %q want %q", e.GetGcid(), env.GCID)
	}
	if e.GetTraceparent() != env.Traceparent {
		t.Fatalf("envelope.traceparent: got %q want %q", e.GetTraceparent(), env.Traceparent)
	}
	if e.GetSchemaVersion() != env.SchemaVersion {
		t.Fatalf("envelope.schema_version: got %d want %d", e.GetSchemaVersion(), env.SchemaVersion)
	}
	if e.GetSourceService() != env.SourceService {
		t.Fatalf("envelope.source_service: got %q want %q", e.GetSourceService(), env.SourceService)
	}
}

func TestWireCompat_ClosureSagaStepCompleted_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"saga_id":              "01971a90-1111-7000-8000-000000000001",
		"gcid":                 env.GCID,
		"step_state":           4, // CLOSURE_STEP_STATE_PSEUDONYMIZED
		"domain_completed":     "governance",
		"records_affected":     int64(42),
		"completed_at":         t0,
		"chora_imda_dimension": "accountability",
		"imda_lifecycle_stage": "runtime",
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.closure.saga_step_completed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}

	var msg governancev1.ClosureSagaStepCompleted
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if msg.GetEnvelope() == nil {
		t.Fatal("envelope not decoded")
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if got := msg.GetSagaId(); got != "01971a90-1111-7000-8000-000000000001" {
		t.Fatalf("saga_id: got %q", got)
	}
	if got := msg.GetGcid(); got != env.GCID {
		t.Fatalf("gcid: got %q", got)
	}
	if got := msg.GetStepState(); got != governancev1.ClosureStepState_CLOSURE_STEP_STATE_PSEUDONYMIZED {
		t.Fatalf("step_state: got %v", got)
	}
	if got := msg.GetDomainCompleted(); got != "governance" {
		t.Fatalf("domain_completed: got %q", got)
	}
	if got := msg.GetRecordsAffected(); got != 42 {
		t.Fatalf("records_affected: got %d", got)
	}
	if got := msg.GetCompletedAt(); got == nil || got.AsTime().Unix() != t0.Unix() {
		t.Fatalf("completed_at not round-tripped: %+v", got)
	}
	if got := msg.GetEnvelope().GetChoraImdaDimension(); got != "accountability" {
		t.Fatalf("envelope.chora_imda_dimension: got %q", got)
	}
	if got := msg.GetEnvelope().GetImdaLifecycleStage(); got != "runtime" {
		t.Fatalf("envelope.imda_lifecycle_stage: got %q", got)
	}
}

func TestWireCompat_ClosureSagaFailed_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"saga_id":           "01971a90-1111-7000-8000-000000000001",
		"gcid":              env.GCID,
		"target_step_state": 4,
		"domain_failed":     "governance",
		"failure_reason":    "DEK delete failed: KMS_TIMEOUT",
		"compensated":       true,
		"failed_at":         t0,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.closure.saga_failed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.ClosureSagaFailed
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if msg.GetSagaId() != "01971a90-1111-7000-8000-000000000001" {
		t.Fatalf("saga_id: got %q", msg.GetSagaId())
	}
	if msg.GetTargetStepState() != governancev1.ClosureStepState_CLOSURE_STEP_STATE_PSEUDONYMIZED {
		t.Fatalf("target_step_state: got %v", msg.GetTargetStepState())
	}
	if msg.GetDomainFailed() != "governance" {
		t.Fatalf("domain_failed: got %q", msg.GetDomainFailed())
	}
	if msg.GetFailureReason() != "DEK delete failed: KMS_TIMEOUT" {
		t.Fatalf("failure_reason: got %q", msg.GetFailureReason())
	}
	if !msg.GetCompensated() {
		t.Fatal("compensated should be true")
	}
	if got := msg.GetFailedAt(); got == nil || got.AsTime().Unix() != t0.Unix() {
		t.Fatalf("failed_at not round-tripped: %+v", got)
	}
}

func TestWireCompat_AuditEntryRecorded_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"audit_id":            "01971a90-2222-7000-8000-000000000001",
		"actor_gcid":          env.GCID,
		"target_resource_uri": "chora://creation/atom/01971a90-aaaa",
		"action":              "atom.publish",
		"result":              1, // AUDIT_RESULT_ALLOWED
		"annotation":          "Routine publish through gatekeeper",
		"source_ip":           "203.0.113.42",
		"user_agent":          "chora-web/1.0",
		"occurred_at":         t0,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.audit.recorded.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.AuditEntryRecorded
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if msg.GetAuditId() != "01971a90-2222-7000-8000-000000000001" {
		t.Fatalf("audit_id: got %q", msg.GetAuditId())
	}
	if msg.GetActorGcid() != env.GCID {
		t.Fatalf("actor_gcid: got %q", msg.GetActorGcid())
	}
	if msg.GetTargetResourceUri() != "chora://creation/atom/01971a90-aaaa" {
		t.Fatalf("target_resource_uri: got %q", msg.GetTargetResourceUri())
	}
	if msg.GetAction() != "atom.publish" {
		t.Fatalf("action: got %q", msg.GetAction())
	}
	if msg.GetResult() != governancev1.AuditResult_AUDIT_RESULT_ALLOWED {
		t.Fatalf("result: got %v", msg.GetResult())
	}
	if got := msg.GetOccurredAt(); got == nil || got.AsTime().Unix() != t0.Unix() {
		t.Fatalf("occurred_at not round-tripped: %+v", got)
	}
}

func TestWireCompat_PolicyViolationDetected_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"violation_id":       "01971a90-3333-7000-8000-000000000001",
		"policy_id":          "policy-content-moderation-v3",
		"policy_kind":        1, // POLICY_KIND_CONTENT_MODERATION
		"violation_severity": 4, // VIOLATION_SEVERITY_HIGH
		"subject_gcid":       env.GCID,
		"resource_uri":       "chora://creation/atom/01971a90-aaaa",
		"description":        "Hate-speech tokens detected by Model Armor",
		"detector":           "model-armor-v1",
		"detected_at":        t0,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.policy.violation_detected.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.PolicyViolationDetected
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if msg.GetViolationId() != "01971a90-3333-7000-8000-000000000001" {
		t.Fatalf("violation_id: got %q", msg.GetViolationId())
	}
	if msg.GetPolicyKind() != governancev1.PolicyKind_POLICY_KIND_CONTENT_MODERATION {
		t.Fatalf("policy_kind: got %v", msg.GetPolicyKind())
	}
	if msg.GetViolationSeverity() != governancev1.ViolationSeverity_VIOLATION_SEVERITY_HIGH {
		t.Fatalf("violation_severity: got %v", msg.GetViolationSeverity())
	}
	if msg.GetSubjectGcid() != env.GCID {
		t.Fatalf("subject_gcid: got %q", msg.GetSubjectGcid())
	}
	if got := msg.GetDetectedAt(); got == nil || got.AsTime().Unix() != t0.Unix() {
		t.Fatalf("detected_at not round-tripped: %+v", got)
	}
}

func TestWireCompat_PolicyPublished_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"policy_id":         "policy-content-moderation-v3",
		"policy_kind":       1,
		"title":             "Content Moderation v3",
		"version":           "3.0.0",
		"policy_uri":        "gs://chora-policies/content-moderation/v3.yaml",
		"scope_tenant_id":   env.TenantID,
		"published_by_gcid": env.GCID,
		"published_at":      t0,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.policy.published.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.PolicyPublished
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if msg.GetPolicyId() != "policy-content-moderation-v3" {
		t.Fatalf("policy_id: got %q", msg.GetPolicyId())
	}
	if msg.GetPolicyKind() != governancev1.PolicyKind_POLICY_KIND_CONTENT_MODERATION {
		t.Fatalf("policy_kind: got %v", msg.GetPolicyKind())
	}
	if msg.GetVersion() != "3.0.0" {
		t.Fatalf("version: got %q", msg.GetVersion())
	}
}

func TestWireCompat_PolicyUpdated_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"policy_id":        "policy-content-moderation-v3",
		"policy_kind":      1,
		"title":            "Content Moderation v3",
		"prior_version":    "2.4.0",
		"version":          "3.0.0",
		"policy_uri":       "gs://chora-policies/content-moderation/v3.yaml",
		"scope_tenant_id":  env.TenantID,
		"updated_by_gcid":  env.GCID,
		"changed_sections": []string{"Section A", "Section B"},
		"updated_at":       t0,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.policy.updated.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.PolicyUpdated
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if msg.GetPriorVersion() != "2.4.0" {
		t.Fatalf("prior_version: got %q", msg.GetPriorVersion())
	}
	if msg.GetVersion() != "3.0.0" {
		t.Fatalf("version: got %q", msg.GetVersion())
	}
	got := msg.GetChangedSections()
	if len(got) != 2 || got[0] != "Section A" || got[1] != "Section B" {
		t.Fatalf("changed_sections: got %+v", got)
	}
}

func TestWireCompat_PolicyRetired_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"policy_id":           "policy-content-moderation-v2",
		"policy_kind":         1,
		"title":               "Content Moderation v2",
		"version":             "2.4.0",
		"scope_tenant_id":     env.TenantID,
		"successor_policy_id": "policy-content-moderation-v3",
		"retired_by_gcid":     env.GCID,
		"reason":              "Superseded by v3",
		"retired_at":          t0,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.policy.retired.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.PolicyRetired
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if msg.GetSuccessorPolicyId() != "policy-content-moderation-v3" {
		t.Fatalf("successor_policy_id: got %q", msg.GetSuccessorPolicyId())
	}
	if msg.GetReason() != "Superseded by v3" {
		t.Fatalf("reason: got %q", msg.GetReason())
	}
}

func TestWireCompat_ImdaDimensionAttested_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"attestation_id":   "01971a90-4444-7000-8000-000000000001",
		"dimension":        1, // IMDA_DIMENSION_ACCOUNTABILITY
		"scope_tenant_id":  env.TenantID,
		"period":           "2026-Q2",
		"evidence_ids":     []string{"ev-1", "ev-2"},
		"attested_by_gcid": env.GCID,
		"attestation_uri":  "gs://chora-imda/attestations/2026-q2/accountability.pdf",
		"attested_at":      t0,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.imda.dimension_attested.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.ImdaDimensionAttested
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if msg.GetDimension() != governancev1.ImdaDimension_IMDA_DIMENSION_ACCOUNTABILITY {
		t.Fatalf("dimension: got %v", msg.GetDimension())
	}
	if msg.GetPeriod() != "2026-Q2" {
		t.Fatalf("period: got %q", msg.GetPeriod())
	}
	gotEv := msg.GetEvidenceIds()
	if len(gotEv) != 2 || gotEv[0] != "ev-1" || gotEv[1] != "ev-2" {
		t.Fatalf("evidence_ids: got %+v", gotEv)
	}
}

func TestWireCompat_ImdaEvidenceGathered_DecodesIntoGeneratedType(t *testing.T) {
	env := wireCompatEnvelope()
	t0 := env.OccurredAt
	payload := map[string]any{
		"evidence_id":      "01971a90-5555-7000-8000-000000000001",
		"dimension":        3, // IMDA_DIMENSION_SAFETY_AND_ROBUSTNESS
		"evidence_uri":     "gs://chora-imda/evidence/2026-q2/redteam.log",
		"caption":          "Red-team eval pack 2026-Q2",
		"scope_tenant_id":  env.TenantID,
		"gathered_by_gcid": env.GCID,
		"gathered_at":      t0,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.imda.evidence_gathered.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	var msg governancev1.ImdaEvidenceGathered
	if err := proto.Unmarshal(bz, &msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	assertEnvelopeRoundTrip(t, env, msg.GetEnvelope())
	if msg.GetDimension() != governancev1.ImdaDimension_IMDA_DIMENSION_SAFETY_AND_ROBUSTNESS {
		t.Fatalf("dimension: got %v", msg.GetDimension())
	}
	if msg.GetCaption() != "Red-team eval pack 2026-Q2" {
		t.Fatalf("caption: got %q", msg.GetCaption())
	}
}
