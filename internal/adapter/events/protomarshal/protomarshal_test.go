// Package protomarshal_test verifies binary protobuf wire-format encoding for
// chora-governance's outbox event payloads. RED tests written BEFORE the
// encoder lands per CLAUDE.md §development-execution + feedback_strict_tdd.
//
// Gap: outbox writer was persisting JSON-marshalled payload bytes that the
// Pub/Sub Schema Registry (BINARY encoding) rejects at publish time with
// "Invalid binary proto message". Fix is producer-side: marshal to canonical
// proto wire bytes before the outbox row is written. Dispatcher passes bytes
// through unchanged.
//
// Mirrors services/chora-consumption/internal/adapter/events/protomarshal/
// protomarshal_test.go — the canonical pattern across the 7 outbox-fix
// agents per task #33.
package protomarshal_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/apollo-chora/chora-governance/internal/adapter/events/protomarshal"
)

// fixedEnvelope returns an envelope with deterministic values for byte-level
// assertions.
func fixedEnvelope() protomarshal.Envelope {
	t := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	return protomarshal.Envelope{
		EventID:        "01971a90-0000-7000-8000-00000000g001",
		IdempotencyKey: "idemp-gov-1",
		TenantID:       "01970000-0000-7000-8000-000000000001",
		GCID:           "01970000-0000-7000-8000-000000000bbb",
		OccurredAt:     t,
		PublishedAt:    t.Add(time.Millisecond),
		Traceparent:    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		Tracestate:     "",
		SourceProject:  "chora-489812",
		SourceService:  "chora-governance",
		SchemaVersion:  1,
	}
}

// walkTopLevelTags walks a top-level message's TLV stream, returning the set
// of field numbers seen. Fails the test on any malformed tag/value record.
func walkTopLevelTags(t *testing.T, bz []byte) map[protowire.Number]bool {
	t.Helper()
	seen := map[protowire.Number]bool{}
	rem := bz
	for len(rem) > 0 {
		num, typ, n := protowire.ConsumeTag(rem)
		if n < 0 {
			t.Fatalf("invalid tag at offset %d", len(bz)-len(rem))
		}
		rem = rem[n:]
		seen[num] = true
		switch typ {
		case protowire.BytesType:
			_, n := protowire.ConsumeBytes(rem)
			if n < 0 {
				t.Fatalf("invalid length-delimited value for field %d", num)
			}
			rem = rem[n:]
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(rem)
			if n < 0 {
				t.Fatalf("invalid varint value for field %d", num)
			}
			rem = rem[n:]
		default:
			t.Fatalf("unexpected wire type %d for field %d", typ, num)
		}
	}
	return seen
}

// envelopeFromBytes extracts and walks the nested envelope (field 1, bytes).
func envelopeFromBytes(t *testing.T, bz []byte) map[protowire.Number]bool {
	t.Helper()
	num, typ, n := protowire.ConsumeTag(bz)
	if num != 1 || typ != protowire.BytesType || n < 0 {
		t.Fatalf("expected envelope tag (1, bytes), got num=%d typ=%d", num, typ)
	}
	envBytes, m := protowire.ConsumeBytes(bz[n:])
	if m < 0 {
		t.Fatal("invalid envelope bytes")
	}
	if len(envBytes) == 0 {
		t.Fatal("empty envelope bytes")
	}
	seen := map[protowire.Number]bool{}
	rem := envBytes
	for len(rem) > 0 {
		num, typ, n := protowire.ConsumeTag(rem)
		if n < 0 {
			t.Fatalf("invalid envelope inner tag")
		}
		rem = rem[n:]
		seen[num] = true
		switch typ {
		case protowire.BytesType:
			_, n := protowire.ConsumeBytes(rem)
			if n < 0 {
				t.Fatalf("invalid envelope inner bytes for field %d", num)
			}
			rem = rem[n:]
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(rem)
			if n < 0 {
				t.Fatalf("invalid envelope inner varint for field %d", num)
			}
			rem = rem[n:]
		}
	}
	return seen
}

// requireEnvelopeMandatoryFields verifies the envelope sub-message contains
// all mandatory chora.common.v1.EventEnvelope fields per CLAUDE.md §6.
func requireEnvelopeMandatoryFields(t *testing.T, seen map[protowire.Number]bool) {
	t.Helper()
	required := []protowire.Number{1, 2, 3, 4, 5, 6, 7, 9, 10, 11}
	for _, want := range required {
		if !seen[want] {
			t.Fatalf("envelope: missing required field %d (seen: %v)", want, seen)
		}
	}
}

// -----------------------------------------------------------------------------
// ClosureSagaStepCompleted (chora.governance.closure.saga_step_completed.v1)
// Field layout per chora-contracts/proto/events-flat/governance/closure/
// saga_step_completed.proto:
//
//	1  bytes  Envelope envelope
//	2  string saga_id
//	3  string gcid
//	4  varint ClosureStepState step_state
//	5  string domain_completed
//	6  varint int64 records_affected
//	7  bytes  Timestamp completed_at
// -----------------------------------------------------------------------------

func TestMarshalClosureSagaStepCompleted_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"saga_id":          "01971a90-1111-7000-8000-000000000001",
		"gcid":             env.GCID,
		"step_state":       4, // CLOSURE_STEP_STATE_PSEUDONYMIZED
		"domain_completed": "governance",
		"records_affected": int64(42),
		"completed_at":     env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.closure.saga_step_completed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("MarshalPayload: empty bytes")
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7} {
		if !seen[want] {
			t.Fatalf("ClosureSagaStepCompleted: missing top-level field %d", want)
		}
	}
	envSeen := envelopeFromBytes(t, bz)
	requireEnvelopeMandatoryFields(t, envSeen)
}

// -----------------------------------------------------------------------------
// ClosureSagaFailed (chora.governance.closure.saga_failed.v1)
// Field layout per chora-contracts/proto/events-flat/governance/closure/
// saga_failed.proto:
//
//	1  bytes  Envelope envelope
//	2  string saga_id
//	3  string gcid
//	4  varint ClosureStepState target_step_state
//	5  string domain_failed
//	6  string failure_reason
//	7  varint bool compensated
//	8  bytes  Timestamp failed_at
// -----------------------------------------------------------------------------

func TestMarshalClosureSagaFailed_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"saga_id":           "01971a90-1111-7000-8000-000000000001",
		"gcid":              env.GCID,
		"target_step_state": 4,
		"domain_failed":     "governance",
		"failure_reason":    "DEK delete failed: KMS_TIMEOUT",
		"compensated":       true,
		"failed_at":         env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.closure.saga_failed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8} {
		if !seen[want] {
			t.Fatalf("ClosureSagaFailed: missing top-level field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// AuditEntryRecorded (chora.governance.audit.recorded.v1)
// Field layout per chora-contracts/proto/events-flat/governance/audit/
// recorded.proto:
//
//	1  bytes  Envelope envelope
//	2  string audit_id
//	3  string actor_gcid
//	4  string target_resource_uri
//	5  string action
//	6  varint AuditResult result
//	7  string annotation
//	8  string source_ip
//	9  string user_agent
//	10 bytes  Timestamp occurred_at
// -----------------------------------------------------------------------------

func TestMarshalAuditEntryRecorded_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"audit_id":            "01971a90-2222-7000-8000-000000000001",
		"actor_gcid":          env.GCID,
		"target_resource_uri": "chora://creation/atom/01971a90-aaaa",
		"action":              "atom.publish",
		"result":              1, // AUDIT_RESULT_ALLOWED
		"annotation":          "Routine publish through gatekeeper",
		"source_ip":           "203.0.113.42",
		"user_agent":          "chora-web/1.0",
		"occurred_at":         env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.audit.recorded.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 10} {
		if !seen[want] {
			t.Fatalf("AuditEntryRecorded: missing top-level field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// PolicyViolationDetected (chora.governance.policy.violation_detected.v1)
// Field layout per chora-contracts/proto/events-flat/governance/policy/
// violation_detected.proto:
//
//	1  bytes  Envelope envelope
//	2  string violation_id
//	3  string policy_id
//	4  varint PolicyKind policy_kind
//	5  varint ViolationSeverity violation_severity
//	6  string subject_gcid
//	7  string resource_uri
//	8  string description
//	9  string detector
//	10 bytes  Timestamp detected_at
// -----------------------------------------------------------------------------

func TestMarshalPolicyViolationDetected_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"violation_id":       "01971a90-3333-7000-8000-000000000001",
		"policy_id":          "policy-content-moderation-v3",
		"policy_kind":        1, // POLICY_KIND_CONTENT_MODERATION
		"violation_severity": 4, // VIOLATION_SEVERITY_HIGH
		"subject_gcid":       env.GCID,
		"resource_uri":       "chora://creation/atom/01971a90-aaaa",
		"description":        "Hate-speech tokens detected by Model Armor",
		"detector":           "model-armor-v1",
		"detected_at":        env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.policy.violation_detected.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("PolicyViolationDetected: missing top-level field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// PolicyPublished (chora.governance.policy.published.v1)
//
//	1  bytes  Envelope envelope
//	2  string policy_id
//	3  varint PolicyKind policy_kind
//	4  string title
//	5  string version
//	6  string policy_uri
//	7  string scope_tenant_id
//	8  string published_by_gcid
//	9  bytes  Timestamp published_at
// -----------------------------------------------------------------------------

func TestMarshalPolicyPublished_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"policy_id":         "policy-content-moderation-v3",
		"policy_kind":       1,
		"title":             "Content Moderation v3",
		"version":           "3.0.0",
		"policy_uri":        "gs://chora-policies/content-moderation/v3.yaml",
		"scope_tenant_id":   env.TenantID,
		"published_by_gcid": env.GCID,
		"published_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.policy.published.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9} {
		if !seen[want] {
			t.Fatalf("PolicyPublished: missing top-level field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// PolicyUpdated (chora.governance.policy.updated.v1)
//
//	1  bytes  Envelope envelope
//	2  string policy_id
//	3  varint PolicyKind policy_kind
//	4  string title
//	5  string prior_version
//	6  string version
//	7  string policy_uri
//	8  string scope_tenant_id
//	9  string updated_by_gcid
//	10 string repeated changed_sections
//	11 bytes  Timestamp updated_at
// -----------------------------------------------------------------------------

func TestMarshalPolicyUpdated_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
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
		"updated_at":       env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.policy.updated.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} {
		if !seen[want] {
			t.Fatalf("PolicyUpdated: missing top-level field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// PolicyRetired (chora.governance.policy.retired.v1)
//
//	1  bytes  Envelope envelope
//	2  string policy_id
//	3  varint PolicyKind policy_kind
//	4  string title
//	5  string version
//	6  string scope_tenant_id
//	7  string successor_policy_id
//	8  string retired_by_gcid
//	9  string reason
//	10 bytes  Timestamp retired_at
// -----------------------------------------------------------------------------

func TestMarshalPolicyRetired_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"policy_id":           "policy-content-moderation-v2",
		"policy_kind":         1,
		"title":               "Content Moderation v2",
		"version":             "2.4.0",
		"scope_tenant_id":     env.TenantID,
		"successor_policy_id": "policy-content-moderation-v3",
		"retired_by_gcid":     env.GCID,
		"reason":              "Superseded by v3",
		"retired_at":          env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.policy.retired.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if !seen[want] {
			t.Fatalf("PolicyRetired: missing top-level field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// ImdaDimensionAttested (chora.governance.imda.dimension_attested.v1)
//
//	1  bytes  Envelope envelope
//	2  string attestation_id
//	3  varint ImdaDimension dimension
//	4  string scope_tenant_id
//	5  string period
//	6  string repeated evidence_ids
//	7  string attested_by_gcid
//	8  string attestation_uri
//	9  bytes  Timestamp attested_at
// -----------------------------------------------------------------------------

func TestMarshalImdaDimensionAttested_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"attestation_id":   "01971a90-4444-7000-8000-000000000001",
		"dimension":        1, // IMDA_DIMENSION_ACCOUNTABILITY
		"scope_tenant_id":  env.TenantID,
		"period":           "2026-Q2",
		"evidence_ids":     []string{"ev-1", "ev-2"},
		"attested_by_gcid": env.GCID,
		"attestation_uri":  "gs://chora-imda/attestations/2026-q2/accountability.pdf",
		"attested_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.imda.dimension_attested.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8, 9} {
		if !seen[want] {
			t.Fatalf("ImdaDimensionAttested: missing top-level field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// ImdaEvidenceGathered (chora.governance.imda.evidence_gathered.v1)
//
//	1  bytes  Envelope envelope
//	2  string evidence_id
//	3  varint ImdaDimension dimension
//	4  string evidence_uri
//	5  string caption
//	6  string scope_tenant_id
//	7  string gathered_by_gcid
//	8  bytes  Timestamp gathered_at
// -----------------------------------------------------------------------------

func TestMarshalImdaEvidenceGathered_RoundTripsBinaryProto(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"evidence_id":      "01971a90-5555-7000-8000-000000000001",
		"dimension":        3, // IMDA_DIMENSION_SAFETY_AND_ROBUSTNESS
		"evidence_uri":     "gs://chora-imda/evidence/2026-q2/redteam.log",
		"caption":          "Red-team eval pack 2026-Q2",
		"scope_tenant_id":  env.TenantID,
		"gathered_by_gcid": env.GCID,
		"gathered_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.imda.evidence_gathered.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	seen := walkTopLevelTags(t, bz)
	for _, want := range []protowire.Number{1, 2, 3, 4, 5, 6, 7, 8} {
		if !seen[want] {
			t.Fatalf("ImdaEvidenceGathered: missing top-level field %d", want)
		}
	}
}

// -----------------------------------------------------------------------------
// Envelope correctness — every wired topic must emit the envelope at field 1
// with all mandatory chora.common.v1.EventEnvelope inner fields populated.
// -----------------------------------------------------------------------------

func TestMarshalAll_EnvelopeIsWireCompatible(t *testing.T) {
	env := fixedEnvelope()
	// Minimal payload — only what's needed to exercise envelope emission.
	for _, topic := range []string{
		"chora.governance.closure.saga_step_completed.v1",
		"chora.governance.closure.saga_failed.v1",
		"chora.governance.audit.recorded.v1",
		"chora.governance.policy.violation_detected.v1",
		"chora.governance.policy.published.v1",
		"chora.governance.policy.updated.v1",
		"chora.governance.policy.retired.v1",
		"chora.governance.imda.dimension_attested.v1",
		"chora.governance.imda.evidence_gathered.v1",
	} {
		t.Run(topic, func(t *testing.T) {
			bz, err := protomarshal.MarshalPayload(topic, env, nil)
			if err != nil {
				t.Fatalf("MarshalPayload(%s): %v", topic, err)
			}
			if len(bz) == 0 {
				t.Fatalf("empty bytes for %s", topic)
			}
			envSeen := envelopeFromBytes(t, bz)
			requireEnvelopeMandatoryFields(t, envSeen)
		})
	}
}

// -----------------------------------------------------------------------------
// Error contracts — unsupported topic + invalid payload types must fail loud.
// -----------------------------------------------------------------------------

func TestMarshal_UnknownTopic_FailsLoud(t *testing.T) {
	env := fixedEnvelope()
	_, err := protomarshal.MarshalPayload("chora.governance.some.unwired.v1", env, nil)
	if err == nil {
		t.Fatal("expected ErrUnsupportedTopic, got nil")
	}
	if !protomarshal.IsUnsupportedTopic(err) {
		t.Fatalf("expected IsUnsupportedTopic(true), got: %v", err)
	}
}

func TestMarshal_NilPayloadProducesEmptyButValidMessage(t *testing.T) {
	env := fixedEnvelope()
	bz, err := protomarshal.MarshalPayload("chora.governance.audit.recorded.v1", env, nil)
	if err != nil {
		t.Fatalf("MarshalPayload: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("nil payload should still produce envelope bytes")
	}
	num, _, n := protowire.ConsumeTag(bz)
	if n < 0 {
		t.Fatal("invalid leading tag")
	}
	if num != 1 {
		t.Fatalf("expected leading field=1 (envelope), got %d", num)
	}
}

func TestMarshal_RejectsStringForInt32Field(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"policy_kind": "not-a-number", // schema demands varint
	}
	_, err := protomarshal.MarshalPayload("chora.governance.policy.violation_detected.v1", env, payload)
	if err == nil {
		t.Fatal("expected type error for policy_kind=string")
	}
}

func TestMarshal_RejectsStringForBoolField(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"compensated": "true", // schema demands bool
	}
	_, err := protomarshal.MarshalPayload("chora.governance.closure.saga_failed.v1", env, payload)
	if err == nil {
		t.Fatal("expected type error for compensated=string")
	}
}

func TestMarshal_RejectsNonTimeOnTimestampField(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"completed_at": "2026-05-16T00:00:00Z", // schema demands time.Time
	}
	_, err := protomarshal.MarshalPayload("chora.governance.closure.saga_step_completed.v1", env, payload)
	if err == nil {
		t.Fatal("expected type error for completed_at=string")
	}
}

func TestMarshal_RejectsIntForStringField(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"saga_id": 12345, // schema demands string
	}
	_, err := protomarshal.MarshalPayload("chora.governance.closure.saga_step_completed.v1", env, payload)
	if err == nil {
		t.Fatal("expected type error for saga_id=int")
	}
}

// TestMarshal_RepeatedString_AcceptsInterfaceSlice — call sites loading
// payloads from JSON-decoded inputs commonly produce []any-of-string. The
// encoder must coerce.
func TestMarshal_RepeatedString_AcceptsInterfaceSlice(t *testing.T) {
	env := fixedEnvelope()
	payload := map[string]any{
		"attestation_id":   "att-1",
		"dimension":        1,
		"scope_tenant_id":  env.TenantID,
		"period":           "2026-Q2",
		"evidence_ids":     []any{"ev-1", "ev-2", "ev-3"},
		"attested_by_gcid": env.GCID,
		"attested_at":      env.OccurredAt,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.imda.dimension_attested.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload with []any evidence_ids: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
}

// TestMarshal_TimePtrAccepted ensures *time.Time is coerced on Timestamp slots.
func TestMarshal_TimePtrAccepted(t *testing.T) {
	env := fixedEnvelope()
	now := env.OccurredAt
	payload := map[string]any{
		"saga_id":      "saga-1",
		"completed_at": &now,
	}
	bz, err := protomarshal.MarshalPayload("chora.governance.closure.saga_step_completed.v1", env, payload)
	if err != nil {
		t.Fatalf("MarshalPayload with *time.Time: %v", err)
	}
	if len(bz) == 0 {
		t.Fatal("empty bytes")
	}
}
