// Tests for the shared IMDA-evidence subscriber (CHO-2260).
//
// Subscribes to chora.governance.evidence.recorded.v1 — the SHARED IMDA-evidence
// topic every domain service emits into (per Tier 5 D17 + evidence.proto). The
// live producer is chora-observability's Familiar-Growth audit lane (CHO-2257),
// which publishes a BINARY-proto governancev1.EvidenceRecorded through its outbox.
// Each message embeds chora.common.v1.EventEnvelope as field 1; the IMDA
// dimension + lifecycle stage ride the envelope (fields 14/15), NOT the payload.
//
// The subscriber unmarshals the binary proto and appends a hash-chained
// audit.Event row via the audit.Repository port — the same append-only IMDA
// D1 accountability + D2 transparency evidence trail that AuditEgressSubscriber
// (CHO-2245) and AuditPaymentsSubscriber write. Rationale (sink decision): the
// generic EvidenceRecorded wire carries none of the structured fields the D1/D2
// evidence-projector aggregates require (agent_id / decision_id / decision_type
// / owner_gcid all NOT NULL) — routing it through the projector would NACK 100%.
// audit_log is kind-agnostic (the `action` column carries the discriminator),
// so the generic evidence lands durably without fabricating fields.
//
// Per RED→GREEN convention these tests reference identifiers that do not yet
// exist in the source tree on first compile. `mustMarshal` + `stubAuditRepo`
// are shared helpers defined in audit_payments_test.go (same events_test pkg).
package events_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"
	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

const (
	erTestTenantID    = "01970000-0000-7000-8000-0000000000f1"
	erTestGCID        = "01970000-0000-7000-8000-0000000000f2"
	erTestEventID     = "01970000-0000-7000-8000-0000000000f3"
	erTestIdem        = "evidence:chora.consumption.familiar.exp_awarded.v1:01970000-0000-7000-8000-0000000000f9"
	erTestFamiliarID  = "01970000-0000-7000-8000-0000000000f4"
	erTestAuditID     = "01970000-0000-7000-8000-0000000000f5"
	erTestSourceTopic = "chora.consumption.familiar.exp_awarded.v1"
	erTestEvidenceTyp = "familiar_growth.exp_awarded"
	erTestTrace       = "00-ffeeddccbbaa99887766554433221100-ffeeddccbbaa0001-01"
)

// evidenceRecordedPayload builds a producer-shaped EvidenceRecorded, mirroring
// exactly what chora-observability's familiar_growth_evidence_publisher.go
// emits: the IMDA dimension + lifecycle stage ride the EventEnvelope (fields
// 14/15), evidence_type = "familiar_growth."+eventType, additional_fields carry
// {familiar_id, audit_id}. Driving tests from this wire-realistic value (not a
// hand-filled struct) is the schema-conformance guard: a proto/field drift
// between producer and consumer surfaces here.
func evidenceRecordedPayload(dimension, evidenceType string) *governancev1.EvidenceRecorded {
	return &governancev1.EvidenceRecorded{
		Envelope: &commonv1.EventEnvelope{
			EventId:            erTestEventID,
			IdempotencyKey:     erTestIdem,
			TenantId:           erTestTenantID,
			Gcid:               erTestGCID,
			OccurredAt:         timestamppb.Now(),
			PublishedAt:        timestamppb.Now(),
			Traceparent:        erTestTrace,
			Tracestate:         "vendor=test",
			SourceProject:      "chora-489812",
			SourceService:      "chora-observability",
			SchemaVersion:      1,
			ChoraImdaDimension: dimension,
			ImdaLifecycleStage: "runtime",
		},
		EvidenceType:    evidenceType,
		SourceEventType: erTestSourceTopic,
		RecordedAt:      timestamppb.Now(),
		PolicyReference: "ADR-227 §Familiar-growth",
		AdditionalFields: map[string]string{
			"familiar_id": erTestFamiliarID,
			"audit_id":    erTestAuditID,
		},
	}
}

func evidenceRecordedAttrs() events.EvidenceRecordedEnvelopeAttrs {
	return events.EvidenceRecordedEnvelopeAttrs{
		EventID:            erTestEventID,
		IdempotencyKey:     erTestIdem,
		TenantID:           erTestTenantID,
		GCID:               erTestGCID,
		Traceparent:        erTestTrace,
		Tracestate:         "vendor=test",
		ChoraImdaDimension: "accountability",
		SchemaVersion:      "1",
	}
}

// -----------------------------------------------------------------------------
// Happy path — D1 accountability evidence lands in audit_log.
// -----------------------------------------------------------------------------

func TestEvidenceRecordedSubscriber_Accountability_HappyPath(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)

	payload := evidenceRecordedPayload("accountability", erTestEvidenceTyp)
	if err := sub.HandleEvidenceRecorded(
		context.Background(), mustMarshal(t, payload), evidenceRecordedAttrs(),
	); err != nil {
		t.Fatalf("handle: %v", err)
	}

	rows, err := repo.Query(context.Background(), audit.QueryFilter{TenantID: erTestTenantID})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row; got %d", len(rows))
	}
	got := rows[0]
	if got.Action != events.ActionEvidenceRecorded {
		t.Errorf("Action = %q; want %q", got.Action, events.ActionEvidenceRecorded)
	}
	if got.Decision != audit.DecisionPermitted {
		t.Errorf("Decision = %q; want permitted", got.Decision)
	}
	if got.SubjectType != "evidence" {
		t.Errorf("SubjectType = %q; want evidence", got.SubjectType)
	}
	// evidence_type is the fine discriminator, indexed via (subject_type, subject_id).
	if got.SubjectID != erTestEvidenceTyp {
		t.Errorf("SubjectID = %q; want evidence_type %q", got.SubjectID, erTestEvidenceTyp)
	}
	if got.Gcid != erTestGCID {
		t.Errorf("Gcid = %q; want %q", got.Gcid, erTestGCID)
	}
	if got.Traceparent != erTestTrace {
		t.Errorf("Traceparent = %q; want %q", got.Traceparent, erTestTrace)
	}
	// The full proto payload must be preserved as auditor-readable JSON.
	if got.After == "" {
		t.Fatalf("After (JSON payload) should be populated, got empty")
	}
	for _, want := range []string{erTestEvidenceTyp, erTestSourceTopic, erTestFamiliarID, erTestAuditID} {
		if !strings.Contains(got.After, want) {
			t.Errorf("After payload missing %q: %s", want, got.After)
		}
	}
	// The reason surfaces the evidence_type + dimension for the O+ trail.
	if !strings.Contains(got.Reason, erTestEvidenceTyp) {
		t.Errorf("Reason should name the evidence_type; got %q", got.Reason)
	}
	if !strings.Contains(strings.ToLower(got.Reason), "accountability") {
		t.Errorf("Reason should carry the imda_dimension; got %q", got.Reason)
	}
}

// The subscriber is dimension-agnostic at the sink (audit_log): a transparency
// (D2) evidence event lands just as an accountability (D1) one does — unlike
// the projector, whose D1/D2 routes reject the generic wire on NOT-NULL fields.
func TestEvidenceRecordedSubscriber_Transparency_AlsoLands(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)

	payload := evidenceRecordedPayload("transparency", "familiar_growth.tier_advanced")
	if err := sub.HandleEvidenceRecorded(
		context.Background(), mustMarshal(t, payload), evidenceRecordedAttrs(),
	); err != nil {
		t.Fatalf("handle: %v", err)
	}
	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: erTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row for a transparency evidence event; got %d", len(rows))
	}
	if !strings.Contains(strings.ToLower(rows[0].Reason), "transparency") {
		t.Errorf("Reason should carry the transparency dimension; got %q", rows[0].Reason)
	}
}

func TestEvidenceRecordedSubscriber_IdempotentReplay(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)

	body := mustMarshal(t, evidenceRecordedPayload("accountability", erTestEvidenceTyp))
	if err := sub.HandleEvidenceRecorded(context.Background(), body, evidenceRecordedAttrs()); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	// Redelivery from at-least-once Pub/Sub — deduped on the inbox key
	// (idempotency_key → event_id), not the audit_log PK (which is a fresh
	// UUIDv7 per Append).
	if err := sub.HandleEvidenceRecorded(context.Background(), body, evidenceRecordedAttrs()); err != nil {
		t.Fatalf("replay should be a no-op: %v", err)
	}
	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: erTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row after replay; got %d", len(rows))
	}
}

// -----------------------------------------------------------------------------
// Fail-loud: binary decode + mandatory-field validation → error (NACK → DLQ).
// -----------------------------------------------------------------------------

func TestEvidenceRecordedSubscriber_MalformedProto_Nacks(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)

	// A JSON assumption (or any non-proto body) must FAIL LOUD, never silently
	// ack-and-drop — the topic is Schema-Registry-bound with encoding=BINARY.
	err := sub.HandleEvidenceRecorded(context.Background(), []byte(`{"evidence_type":"x"}`), evidenceRecordedAttrs())
	if err == nil {
		t.Fatalf("expected decode error for a non-proto (JSON) body")
	}
	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: erTestTenantID})
	if len(rows) != 0 {
		t.Fatalf("malformed payload must append nothing; got %d rows", len(rows))
	}
}

func TestEvidenceRecordedSubscriber_MissingMandatoryFields_Error(t *testing.T) {
	t.Parallel()

	cases := map[string]func(p *governancev1.EvidenceRecorded, a *events.EvidenceRecordedEnvelopeAttrs){
		"missing_event_id": func(p *governancev1.EvidenceRecorded, a *events.EvidenceRecordedEnvelopeAttrs) {
			p.Envelope.EventId = ""
			a.EventID = "" // no fallback either
		},
		"missing_tenant_id": func(p *governancev1.EvidenceRecorded, a *events.EvidenceRecordedEnvelopeAttrs) {
			p.Envelope.TenantId = ""
			a.TenantID = ""
		},
		"missing_gcid": func(p *governancev1.EvidenceRecorded, a *events.EvidenceRecordedEnvelopeAttrs) {
			// audit_log.gcid is UUID NOT NULL — a GCID-less event cannot be
			// recorded, so fail loud rather than fabricate a subject.
			p.Envelope.Gcid = ""
			a.GCID = ""
		},
		"missing_evidence_type": func(p *governancev1.EvidenceRecorded, a *events.EvidenceRecordedEnvelopeAttrs) {
			// evidence_type is the canonical governed-action label + the audit
			// subject discriminator; a blank one is a publisher bug.
			p.EvidenceType = ""
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			repo := audit.NewInMemoryRepository()
			sub := events.NewEvidenceRecordedSubscriber(repo, nil)

			payload := evidenceRecordedPayload("accountability", erTestEvidenceTyp)
			attrs := evidenceRecordedAttrs()
			mutate(payload, &attrs)

			err := sub.HandleEvidenceRecorded(context.Background(), mustMarshal(t, payload), attrs)
			if err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
			if !strings.Contains(err.Error(), "required") {
				t.Fatalf("expected a 'required' error for %s; got %v", name, err)
			}
			rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: erTestTenantID})
			if len(rows) != 0 {
				t.Fatalf("%s must append nothing; got %d rows", name, len(rows))
			}
		})
	}
}

// A repository failure must SURFACE (return error) so the Pub/Sub adapter Nacks
// for redelivery — never a silent ack that loses evidence. stubAuditRepo is
// defined in audit_payments_test.go.
func TestEvidenceRecordedSubscriber_RepoFailureSurfaces(t *testing.T) {
	t.Parallel()
	repo := &stubAuditRepo{appendErr: errors.New("forced")}
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)

	err := sub.HandleEvidenceRecorded(
		context.Background(),
		mustMarshal(t, evidenceRecordedPayload("accountability", erTestEvidenceTyp)),
		evidenceRecordedAttrs(),
	)
	if err == nil {
		t.Fatalf("expected forced repo error to surface (NACK path)")
	}
	if !strings.Contains(err.Error(), "forced") {
		t.Fatalf("expected 'forced' in error; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// eventbus dispatch — nil on success, error on failure.
// -----------------------------------------------------------------------------

func TestEvidenceRecordedHandler_Success(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)
	handler := events.EvidenceRecordedHandler(sub)

	msg := eventbus.Message{
		Payload: mustMarshal(t, evidenceRecordedPayload("accountability", erTestEvidenceTyp)),
		Envelope: envelope.Envelope{
			EventID:  erTestEventID,
			TenantID: erTestTenantID,
			GCID:     erTestGCID,
		},
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

func TestEvidenceRecordedHandler_ErrorContract(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)
	handler := events.EvidenceRecordedHandler(sub)

	if err := handler(context.Background(), eventbus.Message{Payload: []byte("garbage-not-proto")}); err == nil {
		t.Fatal("expected dispatch error on malformed payload")
	}
	if err := (events.EvidenceRecordedHandler(nil))(context.Background(), eventbus.Message{}); err == nil {
		t.Fatal("expected error for a nil subscriber")
	}
}

// -----------------------------------------------------------------------------
// Constants + envelope-attrs lift + SubscribedTopic.
// -----------------------------------------------------------------------------

func TestEvidenceRecordedSubscriber_TopicConstant(t *testing.T) {
	t.Parallel()
	if events.TopicEvidenceRecorded != "chora.governance.evidence.recorded.v1" {
		t.Errorf("topic = %q; want chora.governance.evidence.recorded.v1", events.TopicEvidenceRecorded)
	}
}

func TestEvidenceRecordedSubscriber_SubscribedTopic(t *testing.T) {
	t.Parallel()
	sub := events.NewEvidenceRecordedSubscriber(audit.NewInMemoryRepository(), nil)
	if sub.SubscribedTopic() != events.TopicEvidenceRecorded {
		t.Errorf("SubscribedTopic() = %q; want %q", sub.SubscribedTopic(), events.TopicEvidenceRecorded)
	}
}

func TestEvidenceRecordedAttrsFromEnvelope(t *testing.T) {
	t.Parallel()

	attrs := events.EvidenceRecordedAttrsFromEnvelope(envelope.Envelope{
		EventID:            erTestEventID,
		IdempotencyKey:     erTestIdem,
		TenantID:           erTestTenantID,
		GCID:               erTestGCID,
		Traceparent:        erTestTrace,
		Tracestate:         "vendor=test",
		ChoraImdaDimension: "accountability",
		SchemaVersion:      1,
	})
	if attrs.EventID != erTestEventID {
		t.Errorf("EventID = %q; want %q", attrs.EventID, erTestEventID)
	}
	if attrs.TenantID != erTestTenantID {
		t.Errorf("TenantID = %q; want %q", attrs.TenantID, erTestTenantID)
	}
	if attrs.GCID != erTestGCID {
		t.Errorf("GCID = %q; want %q", attrs.GCID, erTestGCID)
	}
	if attrs.ChoraImdaDimension != "accountability" {
		t.Errorf("ChoraImdaDimension = %q; want accountability", attrs.ChoraImdaDimension)
	}

	if got := events.EvidenceRecordedAttrsFromEnvelope(envelope.Envelope{}); got.EventID != "" {
		t.Fatalf("zero envelope should yield zero attrs; got EventID=%q", got.EventID)
	}
}

// SchemaConformance pins the exact producer wire → sink projection. If the
// EvidenceRecorded proto contract drifts (a renamed/retyped field, or the
// consumer decodes the wrong message), the round-tripped After JSON loses one
// of these producer-set fields and this goes RED. Drives from proto.Marshal —
// the same encoder chora-observability's outbox uses — never a hand-filled map.
func TestEvidenceRecordedSubscriber_SchemaConformance_ProducerWireShape(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)

	// Envelope-only attrs (proto body is authoritative per ADR-167) — proves the
	// subscriber does not depend on Pub/Sub attributes to source mandatory fields.
	payload := evidenceRecordedPayload("accountability", erTestEvidenceTyp)
	if err := sub.HandleEvidenceRecorded(
		context.Background(), mustMarshal(t, payload), events.EvidenceRecordedEnvelopeAttrs{},
	); err != nil {
		t.Fatalf("handle (envelope-only, no attrs): %v", err)
	}
	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: erTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 row from the envelope-complete wire; got %d", len(rows))
	}
	after := rows[0].After
	for _, want := range []string{
		"familiar_growth.exp_awarded",               // evidence_type
		"chora.consumption.familiar.exp_awarded.v1", // source_event_type
		"familiar_id", // additional_fields key
		"ADR-227",     // policy_reference
	} {
		if !strings.Contains(after, want) {
			t.Errorf("producer-wire field %q missing from projected After JSON: %s", want, after)
		}
	}
}

// -----------------------------------------------------------------------------
// Handler projection + fail-loud nil guards.
// -----------------------------------------------------------------------------

func TestEvidenceRecordedHandler_ProjectsToRepo(t *testing.T) {
	t.Parallel()
	repo := audit.NewInMemoryRepository()
	sub := events.NewEvidenceRecordedSubscriber(repo, nil)
	handler := events.EvidenceRecordedHandler(sub)

	if err := handler(context.Background(), eventbus.Message{
		Payload:  mustMarshal(t, evidenceRecordedPayload("accountability", erTestEvidenceTyp)),
		Envelope: envelope.Envelope{TenantID: erTestTenantID},
	}); err != nil {
		t.Fatalf("handler: %v", err)
	}
	rows, _ := repo.Query(context.Background(), audit.QueryFilter{TenantID: erTestTenantID})
	if len(rows) != 1 {
		t.Fatalf("expected 1 row from the handler; got %d", len(rows))
	}
}

func TestEvidenceRecordedHandler_NilSubscriberErrors(t *testing.T) {
	t.Parallel()
	if err := (events.EvidenceRecordedHandler(nil))(context.Background(), eventbus.Message{Payload: []byte("x")}); err == nil {
		t.Fatal("expected error for a nil subscriber")
	}
}

func TestEvidenceRecordedSubscriber_NotInitialised_Errors(t *testing.T) {
	t.Parallel()
	// A subscriber with a nil repo must fail loud rather than no-op.
	var sub events.EvidenceRecordedSubscriber
	err := sub.HandleEvidenceRecorded(
		context.Background(),
		mustMarshal(t, evidenceRecordedPayload("accountability", erTestEvidenceTyp)),
		evidenceRecordedAttrs(),
	)
	if err == nil {
		t.Fatalf("expected not-initialised error for a zero-value subscriber")
	}
}
