// evidence_recorded_binding_test.go — CHO-2260 composition-root guard.
//
// Verifies the EvidenceRecordedSubscriber + eventbus subscription wiring
// main.go uses is reachable + behaves correctly when driven by an in-process
// handler, AND that the subscription is actually registered in main.go's
// source (a dropped registration is the exact W0 defect class this story
// fixes — a topic whose only subscriber was never wired discards every
// message). Lives in `package main` so it hits the SAME exported symbols
// cmd/server/main.go imports.
package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"
	commonv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/common/v1"
	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/governance/v1"

	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
)

func newEvidenceRecordedPayloadBytes(t *testing.T, evidenceType string) []byte {
	t.Helper()
	// Producer wire shape (chora-observability outbox): BINARY-proto
	// EvidenceRecorded with the authoritative EventEnvelope at field 1; the IMDA
	// dimension + lifecycle stage ride the envelope (fields 14/15).
	b, err := proto.Marshal(&governancev1.EvidenceRecorded{
		Envelope: &commonv1.EventEnvelope{
			EventId:            "01970000-0000-7000-8000-00000000ab01",
			IdempotencyKey:     "evidence:chora.consumption.familiar.exp_awarded.v1:src-001",
			TenantId:           "01970000-0000-7000-8000-00000000ab02",
			Gcid:               "01970000-0000-7000-8000-00000000ab03",
			OccurredAt:         timestamppb.New(time.Now().UTC()),
			Traceparent:        "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
			SourceService:      "chora-observability",
			SchemaVersion:      1,
			ChoraImdaDimension: "accountability",
			ImdaLifecycleStage: "runtime",
		},
		EvidenceType:    evidenceType,
		SourceEventType: "chora.consumption.familiar.exp_awarded.v1",
		RecordedAt:      timestamppb.New(time.Now().UTC()),
		AdditionalFields: map[string]string{
			"familiar_id": "01970000-0000-7000-8000-00000000ab04",
			"audit_id":    "01970000-0000-7000-8000-00000000ab05",
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// TestEvidenceRecordedBinding_HandlerDriven exercises the exact composition
// path main.go takes when jetBus != nil: build the audit repo (the sink) +
// the EvidenceRecordedSubscriber, drive the eventbus handler with one canned
// message, and verify an audit_log row landed. Catches a regression where the
// subscriber is wired but the subscription isn't started.
func TestEvidenceRecordedBinding_HandlerDriven(t *testing.T) {
	t.Parallel()

	auditRepo := audit.NewInMemoryRepository()
	sub := govevents.NewEvidenceRecordedSubscriber(auditRepo, nil)
	handler := govevents.EvidenceRecordedHandler(sub)

	msg := eventbus.Message{
		Subject: govevents.TopicEvidenceRecorded,
		Payload: newEvidenceRecordedPayloadBytes(t, "familiar_growth.exp_awarded"),
		Envelope: envelope.Envelope{
			EventID:  "01970000-0000-7000-8000-00000000ab01",
			TenantID: "01970000-0000-7000-8000-00000000ab02",
			GCID:     "01970000-0000-7000-8000-00000000ab03",
		},
	}
	if err := handler(context.Background(), msg); err != nil {
		t.Fatalf("EvidenceRecordedHandler: %v", err)
	}

	rows, err := auditRepo.Query(context.Background(), audit.QueryFilter{
		TenantID: "01970000-0000-7000-8000-00000000ab02",
	})
	if err != nil {
		t.Fatalf("auditRepo.Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("auditRepo recorded = %d; want 1", len(rows))
	}
	if rows[0].Action != govevents.ActionEvidenceRecorded {
		t.Errorf("action = %q; want %q", rows[0].Action, govevents.ActionEvidenceRecorded)
	}
	if rows[0].SubjectID != "familiar_growth.exp_awarded" {
		t.Errorf("subject_id = %q; want familiar_growth.exp_awarded", rows[0].SubjectID)
	}
}

// TestEvidenceRecordedBinding_TopicConstantStable locks the topic constant to
// the provisioned topic — a copy-paste drift would be caught at unit time.
func TestEvidenceRecordedBinding_TopicConstantStable(t *testing.T) {
	t.Parallel()
	if govevents.TopicEvidenceRecorded != "chora.governance.evidence.recorded.v1" {
		t.Errorf(
			"TopicEvidenceRecorded = %q; want chora.governance.evidence.recorded.v1",
			govevents.TopicEvidenceRecorded,
		)
	}
}

// TestEvidenceRecordedBinding_DefaultSubscriptionName documents the expected
// env default — codified so a refactor that renames the env var or default
// also updates this test. Matches the chora-governance.{topic-tail} convention
// used by the audit-payments / audit-egress subscriptions.
func TestEvidenceRecordedBinding_DefaultSubscriptionName(t *testing.T) {
	t.Parallel()
	const want = "chora-governance.evidence-recorded"
	src := readMainSource(t)
	if !strings.Contains(src, want) {
		t.Errorf("main.go does not reference the default subscription name %q", want)
	}
	if !strings.Contains(src, "CHORA_EVIDENCE_RECORDED_SUBSCRIPTION") {
		t.Errorf("main.go does not reference the CHORA_EVIDENCE_RECORDED_SUBSCRIPTION env override")
	}
}

// TestEvidenceRecordedBinding_WiredInMain is the registration guard: it fails
// RED if the EvidenceRecordedSubscriber wiring is dropped from main.go. A
// subscriber that compiles but is never started in main() is the exact
// shredder-class defect CHO-2260 exists to fix — a fix without this guard is
// worthless (every W0 defect here hid behind a green suite).
func TestEvidenceRecordedBinding_WiredInMain(t *testing.T) {
	t.Parallel()
	src := readMainSource(t)
	for _, token := range []string{
		"NewEvidenceRecordedSubscriber(",
		"EvidenceRecordedHandler(",
		"TopicEvidenceRecorded",
	} {
		if !strings.Contains(src, token) {
			t.Errorf("main.go is missing the evidence-recorded wiring token %q (dropped registration → topic discards every message)", token)
		}
	}
}

func readMainSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	return string(b)
}
