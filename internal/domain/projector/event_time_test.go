package projector

import (
	"context"
	"testing"
	"time"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
)

// The projector must carry the event's own timestamp into every evidence
// aggregate it builds. Without this the constructors' new OccurredAt field is
// dead: the consumers would set it, the domain would honour it, and the one
// component in between would drop it, which is exactly the class of gap a
// green unit test on each side cannot see.
func TestProjector_CarriesEventTimeIntoEveryDimension(t *testing.T) {
	at := time.Date(2026, 8, 8, 10, 47, 20, 0, time.UTC)

	cases := []struct {
		name string
		ev   IncomingEvent
		read func(*evidence.InMemoryRepository) (time.Time, bool)
	}{
		{
			name: "D1 accountability",
			ev: IncomingEvent{
				EventID: "t-d1", TenantID: "ten", ImdaDimension: "accountability",
				EventType: "agent.decision", AgentID: "a1", OwnerGcid: "g1",
				DecisionID: "d1", DecisionType: "generate", OccurredAt: at,
			},
			read: func(r *evidence.InMemoryRepository) (time.Time, bool) {
				rows, err := r.QueryAccountability(context.Background(), evidence.QueryFilter{TenantID: "ten"})
				if err != nil || len(rows) != 1 {
					return time.Time{}, false
				}
				return rows[0].RecordedAt, true
			},
		},
		{
			name: "D3 policy violation",
			ev: IncomingEvent{
				EventID: "t-d3", TenantID: "ten", ImdaDimension: "safety_and_robustness",
				EventType: "policy_violation_detected", AgentID: "a1", PolicyName: "p",
				Severity: "high", Detector: "MODEL_ARMOR", OccurredAt: at,
			},
			read: func(r *evidence.InMemoryRepository) (time.Time, bool) {
				rows, err := r.QueryPolicyViolations(context.Background(), evidence.QueryFilter{TenantID: "ten"})
				if err != nil || len(rows) != 1 {
					return time.Time{}, false
				}
				return rows[0].DetectedAt, true
			},
		},
		{
			name: "D3 eval run",
			ev: IncomingEvent{
				EventID: "t-eval", TenantID: "ten", ImdaDimension: "safety_and_robustness",
				EventType: "eval_completed", RunID: "r1", AgentID: "a1", EvalSuite: "s1",
				OccurredAt: at,
			},
			read: func(r *evidence.InMemoryRepository) (time.Time, bool) {
				rows, err := r.QueryEvalRuns(context.Background(), evidence.QueryFilter{TenantID: "ten"})
				if err != nil || len(rows) != 1 {
					return time.Time{}, false
				}
				return rows[0].RunAt, true
			},
		},
		{
			name: "D4 bias run",
			ev: IncomingEvent{
				EventID: "t-bias", TenantID: "ten", ImdaDimension: "fairness_and_human_oversight",
				EventType: "bias_test_completed", RunID: "r1", AgentID: "a1",
				ProtectedAttribute: "demographic", TestType: "deepeval_bias", OccurredAt: at,
			},
			read: func(r *evidence.InMemoryRepository) (time.Time, bool) {
				rows, err := r.QueryBiasTestRuns(context.Background(), evidence.QueryFilter{TenantID: "ten"})
				if err != nil || len(rows) != 1 {
					return time.Time{}, false
				}
				return rows[0].RunAt, true
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := evidence.NewInMemoryRepository()
			if err := New(repo).Project(context.Background(), tc.ev); err != nil {
				t.Fatalf("Project: %v", err)
			}
			got, ok := tc.read(repo)
			if !ok {
				t.Fatal("no row projected")
			}
			if !got.Equal(at) {
				t.Errorf("timestamp = %s, want the event time %s (the projector dropped it)",
					got.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano))
			}
		})
	}
}

// An event with no timestamp must still project, stamped with now.
func TestProjector_MissingEventTimeStillProjects(t *testing.T) {
	repo := evidence.NewInMemoryRepository()
	err := New(repo).Project(context.Background(), IncomingEvent{
		EventID: "t-none", TenantID: "ten", ImdaDimension: "safety_and_robustness",
		EventType: "policy_violation_detected", AgentID: "a1", PolicyName: "p",
		Severity: "high", Detector: "MODEL_ARMOR",
	})
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	rows, err := repo.QueryPolicyViolations(context.Background(), evidence.QueryFilter{TenantID: "ten"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if rows[0].DetectedAt.IsZero() {
		t.Error("DetectedAt is zero; a missing event time must fall back to now")
	}
}
