// branch_tail_test.go — last stragglers in the events package: cost-anomaly
// not-initialised / bad-dimension / decode branches, egress nil-subscriber +
// attrs nil-map branches, the two checkInitialised guards, atoiOrZero,
// canonicaliseHITLDimension alias, and the closure repo failNext branch.
package events

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"

	"github.com/apollo-chora/chora-governance/internal/config"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

func TestTail_CostAnomaly_NotInitialisedAndBadDimension(t *testing.T) {
	t.Parallel()

	// nil subscriber → error
	sub := NewCostAnomalySubscriber(evidence.NewInMemoryRepository(), nil)
	if err := sub.Handle(context.Background(), CostAnomalyEvent{}); err == nil {
		t.Error("uninitialised subscriber should error")
	}

	// repo nil → error
	bare := &CostAnomalySubscriber{}
	if err := bare.Handle(context.Background(), CostAnomalyEvent{}); err == nil {
		t.Error("nil repo should error")
	}

	// wrong dimension → error
	ev := CostAnomalyEvent{
		EventID: "e1", TenantID: "t1", AnomalyID: "a1", AgentID: "ag1",
		ChoraImdaDimension: "accountability", // not D3
	}
	if err := sub.Handle(context.Background(), ev); err == nil {
		t.Error("wrong dimension should error")
	}

	// happy path with explicit D3 dimension
	ev.ChoraImdaDimension = "safety_and_robustness"
	ev.ObservedMicros = 1500
	ev.BaselineMicros = 1000
	if err := sub.Handle(context.Background(), ev); err != nil {
		t.Fatalf("happy path: %v", err)
	}
}

func TestTail_CostAnomaly_DecodeBranches(t *testing.T) {
	t.Parallel()
	sub := NewCostAnomalySubscriber(evidence.NewInMemoryRepository(), nil)

	// empty body
	if err := sub.HandleBytes(context.Background(), nil); err == nil {
		t.Error("empty body should error")
	}
	// malformed JSON
	if err := sub.HandleBytes(context.Background(), []byte("{nope")); err == nil {
		t.Error("bad json should error")
	}
	// valid body
	body := []byte(`{"event_id":"e1","tenant_id":"t1","anomaly_id":"a1","agent_id":"ag1"}`)
	if err := sub.HandleBytes(context.Background(), body); err != nil {
		t.Fatalf("valid body: %v", err)
	}
}

func TestTail_Egress_NilSubscriberAndAttrs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	err := HandleExternalEgressMessage(ctx, nil, eventbus.Message{})
	if err == nil {
		t.Errorf("nil sub: err=%v", err)
	}

	if got := AuditEgressAttrsFromEnvelope(envelope.Envelope{}); got.EventID != "" {
		t.Errorf("zero envelope → %+v", got)
	}
	filled := envelope.Envelope{EventID: "e1", IdempotencyKey: "k", TenantID: "t1"}
	if got := AuditEgressAttrsFromEnvelope(filled); got.EventID != "e1" || got.TenantID != "t1" {
		t.Errorf("filled envelope → %+v", got)
	}
}

func TestTail_CheckInitialised_Guards(t *testing.T) {
	t.Parallel()
	var esub *AuditEgressSubscriber
	if err := esub.checkInitialised(); err == nil {
		t.Error("nil egress sub should fail checkInitialised")
	}
	esub = &AuditEgressSubscriber{}
	if err := esub.checkInitialised(); err == nil {
		t.Error("egress sub without repo should fail checkInitialised")
	}

	var psub *AuditPaymentsSubscriber
	if err := psub.checkInitialised(); err == nil {
		t.Error("nil payments sub should fail checkInitialised")
	}
	psub = &AuditPaymentsSubscriber{}
	if err := psub.checkInitialised(); err == nil {
		t.Error("payments sub without repo should fail checkInitialised")
	}
}

func TestTail_AtoiOrZero(t *testing.T) {
	t.Parallel()
	if atoiOrZero("") != 0 {
		t.Error("empty → 0")
	}
	if atoiOrZero("  ") != 0 {
		t.Error("blank → 0")
	}
	if atoiOrZero("abc") != 0 {
		t.Error("non-numeric → 0")
	}
	if atoiOrZero("7") != 7 {
		t.Error("numeric → parsed")
	}
}

func TestTail_CanonicaliseHITLDimension(t *testing.T) {
	t.Parallel()
	if canonicaliseHITLDimension("operations_management") != expectedHITLDimension {
		t.Error("v1 alias should canonicalise to D4")
	}
	if canonicaliseHITLDimension("OPERATIONS_MANAGEMENT") != expectedHITLDimension {
		t.Error("uppercase alias should canonicalise to D4")
	}
	if canonicaliseHITLDimension("transparency") != "transparency" {
		t.Error("canonical value passes through lowercased")
	}
}

func TestTail_Closure_PseudonymiseFailNext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := NewInMemoryClosureRepo()
	repo.SetFailNext(true)
	if _, err := repo.Pseudonymise(ctx, "t1", "g1", nil); err == nil {
		t.Error("failNext should force an error")
	}
	// now succeeds and counts columns
	rows, err := repo.Pseudonymise(ctx, "t1", "g1", []config.TableSpec{
		{Table: "t", Columns: []config.ColumnSpec{{Column: "a"}, {Column: "b"}}},
	})
	if err != nil {
		t.Fatalf("Pseudonymise: %v", err)
	}
	if rows != 2 {
		t.Errorf("rows = %d; want 2", rows)
	}
	// repeat for same pair → 0 (already pseudonymised)
	rows, err = repo.Pseudonymise(ctx, "t1", "g1", []config.TableSpec{
		{Table: "t", Columns: []config.ColumnSpec{{Column: "a"}}},
	})
	if err != nil {
		t.Fatalf("Pseudonymise(repeat): %v", err)
	}
	if rows != 0 {
		t.Errorf("repeat rows = %d; want 0", rows)
	}
}

var _ = errors.New // keep errors imported if the file is trimmed
