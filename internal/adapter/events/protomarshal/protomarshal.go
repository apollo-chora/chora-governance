// Package protomarshal encodes chora-governance outbox event payloads to
// canonical binary protobuf wire format so the schema registry
// validation (BINARY encoding) passes at publish time.
//
// Why hand-rolled
// ---------------
// Generated Go bindings exist in chora-contracts/gen/go/chora/governance/v1
// (closure / audit / policy / imda) but pulling them into chora-governance
// would add a transitive dep on the contracts gen tree that this service has
// historically kept out of go.mod (per its current dep posture). We use
// google.golang.org/protobuf/encoding/protowire to emit canonical wire bytes
// for the exact subset of fields each Schema Registry schema expects, with
// zero dependency on the generated bindings — same approach as
// services/chora-consumption/internal/adapter/events/protomarshal.
//
// Field numbers + wire types are pinned to chora-contracts/proto/events-flat/
// governance/* — those flat protos ARE the Schema Registry schemas (one
// top-level message; envelope nested at field 1).
//
// Invariants per the Schema Registry binary-encoded protos:
//
//   - Field 1 = envelope (length-delimited nested message)
//   - Envelope nested fields 1..15 follow chora.common.v1.EventEnvelope layout
//   - Timestamps are nested messages: int64 seconds (field 1) + int32 nanos
//     (field 2)
//   - Unknown topics fail loud (ErrUnsupportedTopic) so the publisher can
//     fall back to JSON with a one-shot WARN rather than persisting bytes
//     that the bus will reject.
//
// Per CLAUDE.md §6 — wire format MUST be binary protobuf for Pub/Sub-attached
// topics. JSON encoding is rejected at publish time with "Invalid binary proto
// message".
//
// Mirrors services/chora-consumption/internal/adapter/events/protomarshal —
// canonical pattern across the 7 outbox-fix services per task #33.
package protomarshal

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// Envelope is the producer-side flat shape of chora.common.v1.EventEnvelope
// that the encoder needs. Mirrors services/chora-governance/internal/adapter/
// events.Envelope (closure subscriber + outbox publisher both project onto
// this); defined locally to keep this package import-cycle-free.
type Envelope struct {
	EventID        string
	IdempotencyKey string
	TenantID       string
	GCID           string
	OccurredAt     time.Time
	PublishedAt    time.Time
	Traceparent    string
	Tracestate     string
	SourceProject  string
	SourceService  string
	SchemaVersion  int32
}

// ErrUnsupportedTopic is returned by MarshalPayload when the topic has no
// registered binary encoder. The publisher should fall back to JSON with
// a WARN log + dispatcher will dead-letter rows whose destination topic
// has Schema Registry validation enabled.
var ErrUnsupportedTopic = errors.New("protomarshal: topic has no binary encoder")

// IsUnsupportedTopic reports whether err is (or wraps) ErrUnsupportedTopic.
func IsUnsupportedTopic(err error) bool { return errors.Is(err, ErrUnsupportedTopic) }

// MarshalPayload converts a topic + envelope + loose payload map into the
// canonical binary protobuf wire bytes for that topic's Schema Registry
// schema. Returns ErrUnsupportedTopic if no encoder is registered for the
// supplied topic.
//
// Topics with registered encoders (canonical chora.governance.* schemas
// from chora-contracts/proto/events-flat/governance/*):
//
//   - chora.governance.closure.saga_step_completed.v1
//   - chora.governance.closure.saga_failed.v1
//   - chora.governance.audit.recorded.v1
//   - chora.governance.policy.violation_detected.v1
//   - chora.governance.policy.published.v1
//   - chora.governance.policy.updated.v1
//   - chora.governance.policy.retired.v1
//   - chora.governance.imda.dimension_attested.v1
//   - chora.governance.imda.evidence_gathered.v1
//
// Adding more topics: append a case to the switch + implement
// encode{X}(env, payload) returning the wire bytes.
func MarshalPayload(topic string, env Envelope, payload map[string]any) ([]byte, error) {
	switch topic {
	case "chora.governance.closure.saga_step_completed.v1":
		return encodeClosureSagaStepCompleted(env, payload)
	case "chora.governance.closure.saga_failed.v1":
		return encodeClosureSagaFailed(env, payload)
	case "chora.governance.audit.recorded.v1":
		return encodeAuditEntryRecorded(env, payload)
	case "chora.governance.policy.violation_detected.v1":
		return encodePolicyViolationDetected(env, payload)
	case "chora.governance.policy.published.v1":
		return encodePolicyPublished(env, payload)
	case "chora.governance.policy.updated.v1":
		return encodePolicyUpdated(env, payload)
	case "chora.governance.policy.retired.v1":
		return encodePolicyRetired(env, payload)
	case "chora.governance.imda.dimension_attested.v1":
		return encodeImdaDimensionAttested(env, payload)
	case "chora.governance.imda.evidence_gathered.v1":
		return encodeImdaEvidenceGathered(env, payload)
	case "chora.governance.ai_transparency_notice.acknowledged.v1":
		return encodeAiTransparencyNoticeAcknowledged(env, payload)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTopic, topic)
	}
}

// -----------------------------------------------------------------------------
// ClosureSagaStepCompleted (chora.governance.closure.saga_step_completed.v1)
// chora-contracts/proto/events-flat/governance/closure/saga_step_completed.proto
//
//	1  bytes  Envelope envelope
//	2  string saga_id
//	3  string gcid
//	4  varint ClosureStepState step_state
//	5  string domain_completed
//	6  varint int64 records_affected
//	7  bytes  Timestamp completed_at
// -----------------------------------------------------------------------------

func encodeClosureSagaStepCompleted(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "saga_id")
	enc.stringField(3, "gcid")
	enc.enumField(4, "step_state")
	enc.stringField(5, "domain_completed")
	enc.int64Field(6, "records_affected")
	enc.timestampField(7, "completed_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// ClosureSagaFailed (chora.governance.closure.saga_failed.v1)
// chora-contracts/proto/events-flat/governance/closure/saga_failed.proto
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

func encodeClosureSagaFailed(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "saga_id")
	enc.stringField(3, "gcid")
	enc.enumField(4, "target_step_state")
	enc.stringField(5, "domain_failed")
	enc.stringField(6, "failure_reason")
	enc.boolField(7, "compensated")
	enc.timestampField(8, "failed_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// AuditEntryRecorded (chora.governance.audit.recorded.v1)
// chora-contracts/proto/events-flat/governance/audit/recorded.proto
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

func encodeAuditEntryRecorded(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "audit_id")
	enc.stringField(3, "actor_gcid")
	enc.stringField(4, "target_resource_uri")
	enc.stringField(5, "action")
	enc.enumField(6, "result")
	enc.stringField(7, "annotation")
	enc.stringField(8, "source_ip")
	enc.stringField(9, "user_agent")
	enc.timestampField(10, "occurred_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// PolicyViolationDetected (chora.governance.policy.violation_detected.v1)
// chora-contracts/proto/events-flat/governance/policy/violation_detected.proto
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

func encodePolicyViolationDetected(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "violation_id")
	enc.stringField(3, "policy_id")
	enc.enumField(4, "policy_kind")
	enc.enumField(5, "violation_severity")
	enc.stringField(6, "subject_gcid")
	enc.stringField(7, "resource_uri")
	enc.stringField(8, "description")
	enc.stringField(9, "detector")
	enc.timestampField(10, "detected_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// PolicyPublished (chora.governance.policy.published.v1)
// chora-contracts/proto/events-flat/governance/policy/published.proto
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

func encodePolicyPublished(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "policy_id")
	enc.enumField(3, "policy_kind")
	enc.stringField(4, "title")
	enc.stringField(5, "version")
	enc.stringField(6, "policy_uri")
	enc.stringField(7, "scope_tenant_id")
	enc.stringField(8, "published_by_gcid")
	enc.timestampField(9, "published_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// PolicyUpdated (chora.governance.policy.updated.v1)
// chora-contracts/proto/events-flat/governance/policy/updated.proto
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

func encodePolicyUpdated(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "policy_id")
	enc.enumField(3, "policy_kind")
	enc.stringField(4, "title")
	enc.stringField(5, "prior_version")
	enc.stringField(6, "version")
	enc.stringField(7, "policy_uri")
	enc.stringField(8, "scope_tenant_id")
	enc.stringField(9, "updated_by_gcid")
	enc.repeatedStringField(10, "changed_sections")
	enc.timestampField(11, "updated_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// PolicyRetired (chora.governance.policy.retired.v1)
// chora-contracts/proto/events-flat/governance/policy/retired.proto
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

func encodePolicyRetired(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "policy_id")
	enc.enumField(3, "policy_kind")
	enc.stringField(4, "title")
	enc.stringField(5, "version")
	enc.stringField(6, "scope_tenant_id")
	enc.stringField(7, "successor_policy_id")
	enc.stringField(8, "retired_by_gcid")
	enc.stringField(9, "reason")
	enc.timestampField(10, "retired_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// ImdaDimensionAttested (chora.governance.imda.dimension_attested.v1)
// chora-contracts/proto/events-flat/governance/imda/dimension_attested.proto
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

func encodeImdaDimensionAttested(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "attestation_id")
	enc.enumField(3, "dimension")
	enc.stringField(4, "scope_tenant_id")
	enc.stringField(5, "period")
	enc.repeatedStringField(6, "evidence_ids")
	enc.stringField(7, "attested_by_gcid")
	enc.stringField(8, "attestation_uri")
	enc.timestampField(9, "attested_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// ImdaEvidenceGathered (chora.governance.imda.evidence_gathered.v1)
// chora-contracts/proto/events-flat/governance/imda/evidence_gathered.proto
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

func encodeImdaEvidenceGathered(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "evidence_id")
	enc.enumField(3, "dimension")
	enc.stringField(4, "evidence_uri")
	enc.stringField(5, "caption")
	enc.stringField(6, "scope_tenant_id")
	enc.stringField(7, "gathered_by_gcid")
	enc.timestampField(8, "gathered_at")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// AiTransparencyNoticeAcknowledged (chora.governance.ai_transparency_notice.acknowledged.v1)
// chora-contracts/proto/events-flat/governance/ai_transparency_notice/acknowledged.proto
//
//	1  bytes  Envelope envelope
//	2  string acknowledgement_id
//	3  string gcid
//	4  string disclosure_version
//	5  string surface
//	6  string scope
//	7  bytes  Timestamp first_shown_at
//	8  bytes  Timestamp acknowledged_at
//	9  string locale
//	10 varint bool minor_mode
// -----------------------------------------------------------------------------

func encodeAiTransparencyNoticeAcknowledged(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	envBz, err := encodeEnvelope(env, payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	out = appendLengthDelimited(out, 1, envBz)
	if payload == nil {
		return out, nil
	}

	enc := newFieldEncoder(out, payload)
	enc.stringField(2, "acknowledgement_id")
	enc.stringField(3, "gcid")
	enc.stringField(4, "disclosure_version")
	enc.stringField(5, "surface")
	enc.stringField(6, "scope")
	enc.timestampField(7, "first_shown_at")
	enc.timestampField(8, "acknowledged_at")
	enc.stringField(9, "locale")
	enc.boolField(10, "minor_mode")
	return enc.bytes()
}

// -----------------------------------------------------------------------------
// Envelope (nested in every event message; field layout matches
// chora.common.v1.EventEnvelope as flattened by chora-contracts/internal/
// protoflatten and embedded as a NESTED type in every events-flat schema).
// -----------------------------------------------------------------------------
//
//	1  string event_id
//	2  string idempotency_key
//	3  string tenant_id
//	4  string gcid
//	5  bytes  Timestamp occurred_at
//	6  bytes  Timestamp published_at
//	7  string traceparent
//	8  string tracestate
//	9  string source_project
//	10 string source_service
//	11 varint int32 schema_version
//	12 string correlation_id
//	13 string causation_id
//	14 string chora_imda_dimension
//	15 string imda_lifecycle_stage

func encodeEnvelope(env Envelope, payload map[string]any) ([]byte, error) {
	out := make([]byte, 0, 256)
	if env.EventID != "" {
		out = appendString(out, 1, env.EventID)
	}
	if env.IdempotencyKey != "" {
		out = appendString(out, 2, env.IdempotencyKey)
	}
	if env.TenantID != "" {
		out = appendString(out, 3, env.TenantID)
	}
	if env.GCID != "" {
		out = appendString(out, 4, env.GCID)
	}
	if !env.OccurredAt.IsZero() {
		out = appendLengthDelimited(out, 5, encodeTimestamp(env.OccurredAt))
	}
	if !env.PublishedAt.IsZero() {
		out = appendLengthDelimited(out, 6, encodeTimestamp(env.PublishedAt))
	}
	if env.Traceparent != "" {
		out = appendString(out, 7, env.Traceparent)
	}
	if env.Tracestate != "" {
		out = appendString(out, 8, env.Tracestate)
	}
	if env.SourceProject != "" {
		out = appendString(out, 9, env.SourceProject)
	}
	if env.SourceService != "" {
		out = appendString(out, 10, env.SourceService)
	}
	if env.SchemaVersion > 0 {
		out = appendVarint(out, 11, uint64(uint32(env.SchemaVersion)))
	}

	// Optional IMDA evidence fields sourced from the payload — chora-governance
	// stamps these on closure ack + audit events per closure_subscriber.go.
	if payload != nil {
		if v, ok := payload["correlation_id"].(string); ok && v != "" {
			out = appendString(out, 12, v)
		}
		if v, ok := payload["causation_id"].(string); ok && v != "" {
			out = appendString(out, 13, v)
		}
		if v, ok := payload["chora_imda_dimension"].(string); ok && v != "" {
			out = appendString(out, 14, v)
		}
		if v, ok := payload["imda_lifecycle_stage"].(string); ok && v != "" {
			out = appendString(out, 15, v)
		}
	}
	return out, nil
}

// encodeTimestamp emits the nested google.protobuf.Timestamp wire shape:
//
//	1 varint int64  seconds
//	2 varint int32  nanos
func encodeTimestamp(t time.Time) []byte {
	out := make([]byte, 0, 16)
	t = t.UTC()
	secs := t.Unix()
	nanos := int32(t.Nanosecond())
	if secs != 0 {
		out = appendVarint(out, 1, uint64(secs))
	}
	if nanos != 0 {
		out = appendVarint(out, 2, uint64(uint32(nanos)))
	}
	return out
}

// -----------------------------------------------------------------------------
// fieldEncoder — typed accumulator for the per-message encoders. Centralises
// the type-check + append plumbing so each encode{X} fn stays declarative.
// -----------------------------------------------------------------------------

type fieldEncoder struct {
	buf     []byte
	payload map[string]any
	err     error
}

func newFieldEncoder(buf []byte, payload map[string]any) *fieldEncoder {
	return &fieldEncoder{buf: buf, payload: payload}
}

func (e *fieldEncoder) bytes() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.buf, nil
}

func (e *fieldEncoder) stringField(field protowire.Number, key string) {
	if e.err != nil {
		return
	}
	raw, present := e.payload[key]
	if !present {
		return
	}
	s, ok := raw.(string)
	if !ok {
		e.err = fmt.Errorf("field %s: expected string, got %T", key, raw)
		return
	}
	if s == "" {
		return
	}
	e.buf = appendString(e.buf, field, s)
}

func (e *fieldEncoder) enumField(field protowire.Number, key string) {
	if e.err != nil {
		return
	}
	raw, present := e.payload[key]
	if !present {
		return
	}
	v, ok := asInt32(raw)
	if !ok {
		e.err = fmt.Errorf("field %s: expected int32-convertible enum, got %T", key, raw)
		return
	}
	if v == 0 {
		return
	}
	e.buf = appendVarint(e.buf, field, uint64(uint32(v)))
}

func (e *fieldEncoder) int64Field(field protowire.Number, key string) {
	if e.err != nil {
		return
	}
	raw, present := e.payload[key]
	if !present {
		return
	}
	v, ok := asInt64(raw)
	if !ok {
		e.err = fmt.Errorf("field %s: expected int64-convertible, got %T", key, raw)
		return
	}
	if v == 0 {
		return
	}
	e.buf = appendVarint(e.buf, field, uint64(v))
}

func (e *fieldEncoder) boolField(field protowire.Number, key string) {
	if e.err != nil {
		return
	}
	raw, present := e.payload[key]
	if !present {
		return
	}
	b, ok := raw.(bool)
	if !ok {
		e.err = fmt.Errorf("field %s: expected bool, got %T", key, raw)
		return
	}
	if !b {
		return
	}
	e.buf = appendVarint(e.buf, field, 1)
}

func (e *fieldEncoder) timestampField(field protowire.Number, key string) {
	if e.err != nil {
		return
	}
	raw, present := e.payload[key]
	if !present {
		return
	}
	t, ok := asTime(raw)
	if !ok {
		e.err = fmt.Errorf("field %s: expected time.Time, got %T", key, raw)
		return
	}
	e.buf = appendLengthDelimited(e.buf, field, encodeTimestamp(t))
}

func (e *fieldEncoder) repeatedStringField(field protowire.Number, key string) {
	if e.err != nil {
		return
	}
	raw, present := e.payload[key]
	if !present {
		return
	}
	ss, ok := stringSlice(raw)
	if !ok {
		e.err = fmt.Errorf("field %s: expected []string, got %T", key, raw)
		return
	}
	for _, s := range ss {
		if s == "" {
			continue
		}
		e.buf = appendString(e.buf, field, s)
	}
}

// -----------------------------------------------------------------------------
// Wire-format helpers (thin protowire wrappers; reuse keeps callers tidy).
// -----------------------------------------------------------------------------

func appendString(b []byte, field protowire.Number, v string) []byte {
	b = protowire.AppendTag(b, field, protowire.BytesType)
	b = protowire.AppendString(b, v)
	return b
}

func appendVarint(b []byte, field protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, field, protowire.VarintType)
	b = protowire.AppendVarint(b, v)
	return b
}

func appendLengthDelimited(b []byte, field protowire.Number, payload []byte) []byte {
	b = protowire.AppendTag(b, field, protowire.BytesType)
	b = protowire.AppendBytes(b, payload)
	return b
}

// -----------------------------------------------------------------------------
// Loose-typed payload coercion (in/out: map[string]any).
// -----------------------------------------------------------------------------

func asInt32(v any) (int32, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int32(n), true
	case int32:
		return n, true
	case int64:
		return int32(n), true
	case float32:
		return int32(n), true
	case float64:
		return int32(n), true
	case uint:
		return int32(n), true
	case uint32:
		return int32(n), true
	case uint64:
		return int32(n), true
	default:
		return 0, false
	}
}

func asInt64(v any) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float32:
		return int64(n), true
	case float64:
		return int64(n), true
	case uint:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	default:
		return 0, false
	}
}

func asTime(v any) (time.Time, bool) {
	if v == nil {
		return time.Time{}, false
	}
	switch t := v.(type) {
	case time.Time:
		return t, true
	case *time.Time:
		if t == nil {
			return time.Time{}, false
		}
		return *t, true
	default:
		return time.Time{}, false
	}
}

func stringSlice(v any) ([]string, bool) {
	if v == nil {
		return nil, false
	}
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			str, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, str)
		}
		return out, true
	default:
		return nil, false
	}
}
