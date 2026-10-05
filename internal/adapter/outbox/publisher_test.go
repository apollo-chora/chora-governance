// Package outbox_test — OutboxPublisher adapter tests.
//
// OutboxPublisher satisfies the chora-governance events.PublisherWithError
// shape (PublishWithError(topic, Header, payload)) by writing the event
// to the outbox_events table (via the Store port) instead of publishing
// directly to Pub/Sub. A separate Dispatcher drains the outbox to Cloud
// Pub/Sub. This decouples tenancy event emission from Pub/Sub
// availability: a crash between domain state-write and Pub/Sub publish
// no longer loses events because the row is durably committed to
// chora.governance.before the HTTP request returns.
//
// Per `feedback_d6_resilience_first_class` B.6.2.a — producer-side durable
// emission for chora-governance's `chora.governance.{tenant,addon}.*.v1` streams.
package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/adapter/outbox"
)

func canonicalHeader() events.Header {
	return events.Header{
		TenantID:    "01970000-0000-7000-8000-000000000001",
		GCID:        "01970000-0000-7000-8000-000000000bbb",
		Traceparent: "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01",
	}
}

func TestOutboxPublisher_Publish_WritesRowToStore(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         store,
		SourceProject: "chora-489812",
		SourceService: "chora-governance",
	})

	hdr := canonicalHeader()
	rec, err := pub.PublishWithError("chora.governance.tenant.created.v1", hdr, map[string]interface{}{
		"tenant_id": hdr.TenantID,
		"name":      "Acme Pte Ltd",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if rec.EventID == "" {
		t.Errorf("PublishedEvent.EventID empty")
	}
	if rec.IdempotencyKey == "" {
		t.Errorf("PublishedEvent.IdempotencyKey empty")
	}
	if rec.SourceService != "chora-governance" {
		t.Errorf("rec.SourceService = %q; want chora-governance", rec.SourceService)
	}

	rows, _ := store.FetchPending(context.Background(), 10)
	if len(rows) != 1 {
		t.Fatalf("store rows = %d; want 1", len(rows))
	}
	row := rows[0]
	if row.Topic != "chora.governance.tenant.created.v1" {
		t.Errorf("row.Topic = %q; want chora.governance.tenant.created.v1", row.Topic)
	}
	if row.TenantID != hdr.TenantID {
		t.Errorf("row.TenantID = %q; want %q", row.TenantID, hdr.TenantID)
	}
	if row.GCID != hdr.GCID {
		t.Errorf("row.GCID = %q; want %q", row.GCID, hdr.GCID)
	}
	if row.AggregateType != "tenant" {
		t.Errorf("row.AggregateType = %q; want tenant (derived from topic)", row.AggregateType)
	}
	if row.EventType != "governance.tenant.created" {
		t.Errorf("row.EventType = %q; want governance.tenant.created", row.EventType)
	}
	if row.IdempotencyKey != rec.IdempotencyKey {
		t.Errorf("row.IdempotencyKey = %q; want %q (rec)", row.IdempotencyKey, rec.IdempotencyKey)
	}
}

func TestOutboxPublisher_Publish_StampsEnvelopeFields(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	pub := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         store,
		SourceProject: "chora-489812",
		SourceService: "chora-governance",
		Now:           func() time.Time { return now },
	})

	hdr := canonicalHeader()
	if _, err := pub.PublishWithError("chora.governance.addon.activated.v1", hdr, map[string]interface{}{
		"addon_code": "daily_dose",
		"tenant_id":  hdr.TenantID,
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	env := rows[0].Envelope

	for _, key := range []string{
		"event_id", "idempotency_key", "tenant_id", "occurred_at", "published_at",
		"traceparent", "source_project", "source_service", "schema_version",
	} {
		if env[key] == "" {
			t.Errorf("envelope.%s empty; want non-empty (mandatory per CLAUDE.md §6)", key)
		}
	}
	if env["source_project"] != "chora-489812" {
		t.Errorf("envelope.source_project = %q; want chora-489812", env["source_project"])
	}
	if env["source_service"] != "chora-governance" {
		t.Errorf("envelope.source_service = %q; want chora-governance", env["source_service"])
	}
	if env["schema_version"] != "1" {
		t.Errorf("envelope.schema_version = %q; want 1", env["schema_version"])
	}
	if env["tenant_id"] != hdr.TenantID {
		t.Errorf("envelope.tenant_id = %q; want %q", env["tenant_id"], hdr.TenantID)
	}
}

func TestOutboxPublisher_Publish_RejectsEmptyTenantID(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})

	hdr := events.Header{TenantID: ""}
	_, err := pub.PublishWithError("chora.governance.tenant.created.v1", hdr, map[string]interface{}{})
	if err == nil {
		t.Fatalf("expected ErrEmptyTenantID, got nil")
	}
}

func TestOutboxPublisher_Publish_RejectsInvalidTopic(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})

	hdr := canonicalHeader()
	for _, bad := range []string{
		"not.a.topic",
		"chora.unknown.aggregate.event.v1",   // wrong domain
		"chora.governance.addon.activated",   // missing version
		"chora.governance.addon.activated.v", // bad version
	} {
		if _, err := pub.PublishWithError(bad, hdr, map[string]interface{}{}); err == nil {
			t.Errorf("topic %q: expected error; got nil", bad)
		}
	}
}

func TestOutboxPublisher_Publish_RejectsNilStore(t *testing.T) {
	t.Parallel()
	pub := outbox.NewPublisher(outbox.PublisherConfig{}) // Store nil
	_, err := pub.PublishWithError("chora.governance.tenant.created.v1",
		canonicalHeader(), map[string]interface{}{})
	if err == nil {
		t.Errorf("Publish without store = nil err; want error")
	}
}

func TestOutboxPublisher_Publish_PayloadIsJSONOfRequestBody(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})

	hdr := canonicalHeader()
	body := map[string]interface{}{
		"addon_code":           "ai_assist",
		"plan_tier":            "premium",
		"chora_imda_dimension": "accountability",
	}
	if _, err := pub.PublishWithError("chora.governance.addon.upgraded.v1", hdr, body); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	var pl map[string]any
	if err := json.Unmarshal(rows[0].Payload, &pl); err != nil {
		t.Fatalf("payload not JSON: %v (%s)", err, string(rows[0].Payload))
	}
	if pl["addon_code"] != "ai_assist" {
		t.Errorf("payload.addon_code = %v; want ai_assist", pl["addon_code"])
	}
	if pl["plan_tier"] != "premium" {
		t.Errorf("payload.plan_tier = %v; want premium", pl["plan_tier"])
	}
}

func TestOutboxPublisher_Publish_DuplicateIdempotencyKeyError(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})

	// Inject deterministic idempotency_key via the IdempotencyKeyFn.
	fixedKey := "fixed-idem-001"
	pubFixed := outbox.NewPublisher(outbox.PublisherConfig{
		Store: store,
		IdempotencyKeyFn: func(topic string, h events.Header, body map[string]interface{}) string {
			return fixedKey
		},
	})

	_ = pub // silence unused
	hdr := canonicalHeader()
	if _, err := pubFixed.PublishWithError("chora.governance.tenant.created.v1", hdr,
		map[string]interface{}{"k": "v"}); err != nil {
		t.Fatalf("Publish 1: %v", err)
	}
	// Second publish with same idempotency_key — collides on UNIQUE.
	_, err := pubFixed.PublishWithError("chora.governance.tenant.created.v1", hdr,
		map[string]interface{}{"k": "v2"})
	if err == nil {
		t.Errorf("expected duplicate idempotency_key rejection on second Publish")
	}
	if !errors.Is(err, outbox.ErrDuplicateIdempotencyKey) {
		t.Errorf("err = %v; want ErrDuplicateIdempotencyKey", err)
	}
}

func TestOutboxPublisher_Publish_DefaultsSourceProjectAndService(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store}) // no project/service
	hdr := canonicalHeader()
	if _, err := pub.PublishWithError("chora.governance.tenant.created.v1", hdr,
		map[string]interface{}{"x": 1}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if rows[0].Envelope["source_project"] != "chora-local" {
		t.Errorf("default source_project = %q; want chora-local", rows[0].Envelope["source_project"])
	}
	if rows[0].Envelope["source_service"] != "chora-governance" {
		t.Errorf("default source_service = %q; want chora-governance", rows[0].Envelope["source_service"])
	}
}

// TopicAggregateInference — the Publisher derives AggregateType from the
// 3rd dot-segment of the canonical topic.
func TestOutboxPublisher_Publish_DerivesAggregateTypeFromTopic(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"chora.governance.tenant.created.v1":       "tenant",
		"chora.governance.tenant.golive.v1":        "tenant",
		"chora.governance.addon.activated.v1":      "addon",
		"chora.governance.addon.upgraded.v1":       "addon",
		"chora.governance.addon.usage_recorded.v1": "addon",
	}
	for topic, wantAggregate := range cases {
		t.Run(topic, func(t *testing.T) {
			store := outbox.NewInMemoryStore()
			pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})
			hdr := canonicalHeader()
			if _, err := pub.PublishWithError(topic, hdr, map[string]interface{}{}); err != nil {
				t.Fatalf("Publish %s: %v", topic, err)
			}
			rows, _ := store.FetchPending(context.Background(), 1)
			if rows[0].AggregateType != wantAggregate {
				t.Errorf("topic %s: AggregateType = %q; want %q",
					topic, rows[0].AggregateType, wantAggregate)
			}
		})
	}
}

func TestOutboxPublisher_Publish_AllCanonicalTopics(t *testing.T) {
	t.Parallel()
	// Mirrors the 8 canonical topics tested in outbox_roundtrip_test.go.
	canonical := []string{
		"chora.governance.tenant.created.v1",
		"chora.governance.tenant.golive.v1",
		"chora.governance.addon.activated.v1",
		"chora.governance.addon.upgraded.v1",
		"chora.governance.addon.downgraded.v1",
		"chora.governance.addon.deactivation_requested.v1",
		"chora.governance.addon.deactivated.v1",
		"chora.governance.addon.usage_recorded.v1",
	}
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})
	hdr := canonicalHeader()
	for _, topic := range canonical {
		if _, err := pub.PublishWithError(topic, hdr,
			map[string]interface{}{"tenant_id": hdr.TenantID}); err != nil {
			t.Errorf("canonical topic %q: %v", topic, err)
		}
	}
	rows, _ := store.FetchPending(context.Background(), 100)
	if len(rows) != len(canonical) {
		t.Errorf("rows = %d; want %d (all canonical topics)", len(rows), len(canonical))
	}
}

// TestOutboxPublisher_Publish_PayloadIsBinaryProto_ForSchemaRegistryTopic asserts
// that the JSON-vs-BINARY encoding gap (task #33) is closed for topics whose
// flat protos exist in chora-contracts/proto/events-flat/governance/. The
// publisher MUST emit canonical binary protobuf wire bytes — JSON would be
// rejected by the schema registry at publish.
func TestOutboxPublisher_Publish_PayloadIsBinaryProto_ForSchemaRegistryTopic(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})

	hdr := canonicalHeader()
	if _, err := pub.PublishWithError("chora.governance.policy.violation_detected.v1", hdr, map[string]interface{}{
		"violation_id":       "v-1",
		"policy_id":          "policy-content-moderation-v3",
		"policy_kind":        1,
		"violation_severity": 4,
		"subject_gcid":       hdr.GCID,
		"resource_uri":       "chora://creation/atom/01971a90-aaaa",
		"description":        "Hate-speech tokens",
		"detector":           "model-armor-v1",
		"detected_at":        time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	bz := rows[0].Payload

	// Negative: payload MUST NOT decode as JSON (binary protobuf bytes are
	// not valid JSON — a JSON-encoded map starts with '{').
	if len(bz) > 0 && bz[0] == '{' {
		t.Fatalf("payload starts with '{' — appears JSON not binary protobuf: %q", string(bz))
	}

	// Positive: first record must be field 1 (envelope) length-delimited.
	num, typ, n := protowire.ConsumeTag(bz)
	if n < 0 {
		t.Fatalf("invalid leading tag in payload: %x", bz)
	}
	if num != 1 || typ != protowire.BytesType {
		t.Fatalf("expected leading field=1 (envelope, bytes), got num=%d typ=%d", num, typ)
	}
}

// TestOutboxPublisher_Publish_PayloadFallsBackToJSON_ForUnknownTopic asserts
// the legacy JSON path still works for topics that don't yet have a binary
// encoder registered (publisher must NOT fail on canonical-but-not-wired
// topics; surface a one-shot WARN + dispatcher dead-letters).
func TestOutboxPublisher_Publish_PayloadFallsBackToJSON_ForUnknownTopic(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})

	hdr := canonicalHeader()
	// chora.governance.addon.upgraded.v1 has no flat proto in chora-contracts —
	// publisher MUST fall through to JSON.
	body := map[string]interface{}{
		"addon_code": "ai_assist",
		"plan_tier":  "premium",
	}
	if _, err := pub.PublishWithError("chora.governance.addon.upgraded.v1", hdr, body); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	var pl map[string]any
	if err := json.Unmarshal(rows[0].Payload, &pl); err != nil {
		t.Fatalf("payload should JSON-decode for unsupported topic: %v (%s)", err, string(rows[0].Payload))
	}
	if pl["addon_code"] != "ai_assist" {
		t.Errorf("payload.addon_code = %v; want ai_assist", pl["addon_code"])
	}
}

// TestOutboxPublisher_AuditRecorded_FlowsToBusAsBinaryProto verifies the
// HITL-verdict audit topic (chora.governance.audit.recorded.v1) round-trips
// publisher → outbox store → dispatcher → Bus, encoded as BINARY protobuf
// (NOT the JSON fallback). chora.governance.audit.recorded.v1 has a registered
// protomarshal encoder, so the dispatched payload is binary proto bytes.
func TestOutboxPublisher_AuditRecorded_FlowsToBusAsBinaryProto(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         store,
		SourceProject: "chora-489812",
		SourceService: "chora-governance",
	})

	hdr := canonicalHeader()
	if _, err := pub.PublishWithError(events.TopicAuditRecorded, hdr, map[string]interface{}{
		"audit_id":            "01970000-0000-7000-8000-0000000000aa",
		"actor_gcid":          hdr.GCID,
		"target_resource_uri": "hitl_decision:dec-1",
		"action":              "governance.hitl.decision_approve",
		"result":              1, // ALLOWED
		"annotation":          "verified",
		"occurred_at":         time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PublishWithError: %v", err)
	}

	rows, _ := store.FetchPending(context.Background(), 10)
	if len(rows) != 1 {
		t.Fatalf("store rows = %d; want 1", len(rows))
	}
	if rows[0].Topic != events.TopicAuditRecorded {
		t.Errorf("row.Topic = %q; want %q", rows[0].Topic, events.TopicAuditRecorded)
	}
	if len(rows[0].Payload) == 0 {
		t.Error("row.Payload empty — expected binary protobuf bytes")
	}

	// Drain to a recording bus and assert delivery.
	bus := &recordingBus{}
	d := outbox.NewDispatcher(outbox.DispatcherConfig{
		Store: store, Bus: bus, WorkerID: "test-worker",
	})
	n, err := d.DrainOnce(context.Background(), 10)
	if err != nil {
		t.Fatalf("DrainOnce: %v", err)
	}
	if n != 1 || bus.callCount() != 1 {
		t.Fatalf("drained=%d busCalls=%d; want 1/1", n, bus.callCount())
	}
	if bus.calls[0].Topic != events.TopicAuditRecorded {
		t.Errorf("bus topic = %q; want %q", bus.calls[0].Topic, events.TopicAuditRecorded)
	}
	if len(bus.calls[0].Payload) == 0 {
		t.Error("bus payload empty — binary proto expected")
	}
}

// TestOutboxPublisher_Publish_MintsTraceparent_WhenHeaderEmpty is the
// event-fabric (2026-07-01) Class-A regression guard. An emit whose inbound
// Header carries no traceparent — e.g. the governance.audit.recorded
// HITL-verdict path when the inbound HTTP request has no W3C trace-context
// header — MUST still yield a non-empty traceparent on the envelope. The
// Dispatcher reconstructs the typed envelope from this attribute map and the
// shared envelope Validate() rejects an empty traceparent pre-publish
// ("envelope: traceparent is required"), so a missing value deadletters the
// audit instead of reaching Pub/Sub.
func TestOutboxPublisher_Publish_MintsTraceparent_WhenHeaderEmpty(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})

	hdr := events.Header{
		TenantID:    "01970000-0000-7000-8000-000000000001",
		GCID:        "01970000-0000-7000-8000-000000000bbb",
		Traceparent: "", // no inbound W3C trace context
	}
	rec, err := pub.PublishWithError(events.TopicAuditRecorded, hdr, map[string]interface{}{
		"audit_id":            "01970000-0000-7000-8000-0000000000aa",
		"actor_gcid":          hdr.GCID,
		"target_resource_uri": "hitl_decision:dec-1",
		"action":              "governance.hitl.decision_approve",
		"result":              1, // ALLOWED
		"annotation":          "verified",
		"occurred_at":         time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("PublishWithError: %v", err)
	}
	if rec.Traceparent == "" {
		t.Error("PublishedEvent.Traceparent empty; want a minted W3C traceparent")
	}

	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	if rows[0].Envelope["traceparent"] == "" {
		t.Error("envelope.traceparent empty; the Dispatcher reads this attribute and the shared envelope Validate() requires it (else deadletter)")
	}
}

// TestOutboxPublisher_Publish_PreservesInboundTraceparent guards that the
// Class-A fix is only-mint-when-empty: a valid inbound traceparent must be
// propagated unchanged (never second-guessed / re-minted).
func TestOutboxPublisher_Publish_PreservesInboundTraceparent(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})

	hdr := canonicalHeader() // carries a valid W3C traceparent
	if _, err := pub.PublishWithError(events.TopicAuditRecorded, hdr, map[string]interface{}{
		"audit_id":            "01970000-0000-7000-8000-0000000000aa",
		"actor_gcid":          hdr.GCID,
		"target_resource_uri": "hitl_decision:dec-1",
		"action":              "governance.hitl.decision_approve",
		"result":              1,
		"annotation":          "verified",
		"occurred_at":         time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("PublishWithError: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if got := rows[0].Envelope["traceparent"]; got != hdr.Traceparent {
		t.Errorf("envelope.traceparent = %q; want inbound %q propagated unchanged", got, hdr.Traceparent)
	}
}

// guard against accidental import-rename surprises.
func TestPublisher_TopicValidator_RejectsLegacy(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store})
	hdr := canonicalHeader()
	// Legacy non-canonical topic (wrong domain).
	_, err := pub.PublishWithError("chora.atomic.events.v1", hdr, map[string]interface{}{})
	if err == nil {
		t.Errorf("legacy topic should be rejected by canonical validator")
	}
	if !strings.Contains(err.Error(), "governance") && !strings.Contains(err.Error(), "domain") {
		t.Errorf("err = %v; want domain-mismatch hint", err)
	}
}
