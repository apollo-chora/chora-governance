// cost_anomaly_subscriber_test.go — unit tests for the D3 cost-anomaly
// evidence ingestion subscriber (Task 3 canonical non-agentic source).
package events_test

import (
	"context"
	"encoding/json"
	"testing"

	govevents "github.com/apollo-chora/chora-governance/internal/adapter/events"
	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

func costAnomalyBytes(t *testing.T, ev govevents.CostAnomalyEvent) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func validCostAnomaly() govevents.CostAnomalyEvent {
	return govevents.CostAnomalyEvent{
		EventID:        "ev-1",
		TenantID:       "tenant-1",
		AnomalyID:      "anom-1",
		AgentID:        "qgen_crew",
		BaselineMicros: 1000,
		ObservedMicros: 9000,
		SigmaFactor:    4.2,
	}
}

func TestCostAnomalySubscriber_HappyPathAppendsEvidence(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	sub := govevents.NewCostAnomalySubscriber(repo, nil)

	if err := sub.HandleBytes(context.Background(), costAnomalyBytes(t, validCostAnomaly())); err != nil {
		t.Fatalf("HandleBytes: %v", err)
	}
	rows, err := repo.QueryCostAnomalies(context.Background(), evidence.QueryFilter{TenantID: "tenant-1"})
	if err != nil {
		t.Fatalf("QueryCostAnomalies: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	if rows[0].AnomalyID != "anom-1" || rows[0].SigmaFactor != 4.2 {
		t.Errorf("row = %+v; mismatch", rows[0])
	}
	if rows[0].LifecycleStage != evidence.LifecycleRuntime {
		t.Errorf("lifecycle = %q; want runtime default", rows[0].LifecycleStage)
	}
}

func TestCostAnomalySubscriber_IdempotentOnEventID(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	sub := govevents.NewCostAnomalySubscriber(repo, nil)
	body := costAnomalyBytes(t, validCostAnomaly())

	for i := 0; i < 3; i++ {
		if err := sub.HandleBytes(context.Background(), body); err != nil {
			t.Fatalf("HandleBytes #%d: %v", i, err)
		}
	}
	rows, _ := repo.QueryCostAnomalies(context.Background(), evidence.QueryFilter{TenantID: "tenant-1"})
	if len(rows) != 1 {
		t.Errorf("rows = %d; want 1 (idempotent re-delivery)", len(rows))
	}
}

func TestCostAnomalySubscriber_MalformedBodyFailsLoud(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	sub := govevents.NewCostAnomalySubscriber(repo, nil)
	if err := sub.HandleBytes(context.Background(), []byte(`{not json`)); err == nil {
		t.Error("malformed body must fail loud (NACK → DLQ), got nil")
	}
}

func TestCostAnomalySubscriber_RejectsMissingMandatoryFields(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	sub := govevents.NewCostAnomalySubscriber(repo, nil)

	cases := map[string]func(*govevents.CostAnomalyEvent){
		"no event_id":   func(e *govevents.CostAnomalyEvent) { e.EventID = "" },
		"no tenant_id":  func(e *govevents.CostAnomalyEvent) { e.TenantID = "" },
		"no anomaly_id": func(e *govevents.CostAnomalyEvent) { e.AnomalyID = "" },
		"no agent_id":   func(e *govevents.CostAnomalyEvent) { e.AgentID = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			ev := validCostAnomaly()
			mut(&ev)
			if err := sub.HandleBytes(context.Background(), costAnomalyBytes(t, ev)); err == nil {
				t.Errorf("%s: want validation error, got nil", name)
			}
		})
	}
}

func TestCostAnomalySubscriber_RejectsWrongDimension(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	sub := govevents.NewCostAnomalySubscriber(repo, nil)
	ev := validCostAnomaly()
	ev.ChoraImdaDimension = "accountability" // wrong — this subscriber is D3
	if err := sub.HandleBytes(context.Background(), costAnomalyBytes(t, ev)); err == nil {
		t.Error("wrong imda_dimension must be rejected")
	}
}

func TestCostAnomalySubscriber_AcceptsBlankDimension(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	sub := govevents.NewCostAnomalySubscriber(repo, nil)
	ev := validCostAnomaly()
	ev.ChoraImdaDimension = "" // omitted — tolerated; row still stamped D3
	if err := sub.HandleBytes(context.Background(), costAnomalyBytes(t, ev)); err != nil {
		t.Errorf("blank dimension should be tolerated: %v", err)
	}
}

func TestNewCostAnomalySubscriber_PanicsOnNilRepo(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on nil repo")
		}
	}()
	govevents.NewCostAnomalySubscriber(nil, nil)
}
