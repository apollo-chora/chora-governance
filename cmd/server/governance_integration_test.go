//go:build integration

// governance_integration_test.go — //go:build integration tagged end-to-end
// smoke for chora-governance. Runs in Cloud Build stage 3 (integration-test)
// via `go test -race -tags=integration ./...`.
//
// Exercises the cross-RPC choreography that the unit bufconn tests don't
// cover end-to-end: RecordAssessment emits a per-dimension score; the same
// dimension immediately shows in GetIMDADashboard. Reuses
// startBufconnGovernanceServer from grpc_test.go (same `package main`).
//
// Per [[feedback-no-stubs-real-wiring]]: real gRPC server over real bufconn
// over real in-memory repos — no mocks anywhere.
package main

import (
	"context"
	"testing"
	"time"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/governance/v1"
)

// TestIntegration_RecordAssessment_ReflectedInDashboard verifies the canonical
// audit-trail invariant: every RecordAssessment for a given (tenant_id, dimension)
// MUST be visible via the very next GetIMDADashboard call. This is the
// contract the O+ surface relies on for "Latest evidence" tile freshness.
func TestIntegration_RecordAssessment_ReflectedInDashboard(t *testing.T) {
	t.Parallel()
	conn, cleanup := startBufconnGovernanceServer(t)
	defer cleanup()

	client := governancev1.NewGovernanceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tenantID := "01970000-0000-7000-8000-0000000a55e5"
	const score int32 = 92

	if _, err := client.RecordAssessment(ctx, &governancev1.RecordAssessmentRequest{
		TenantId:     tenantID,
		Dimension:    governancev1.IMDADimension_IMDA_DIMENSION_TRANSPARENCY,
		Score:        score,
		Indicators:   []string{"model-card-published", "agent-trace-emitted"},
		AssessorGcid: "01970000-0000-7000-9000-0000000a55e5",
	}); err != nil {
		t.Fatalf("RecordAssessment: %v", err)
	}

	dash, err := client.GetIMDADashboard(ctx, &governancev1.GetIMDADashboardRequest{TenantId: tenantID})
	if err != nil {
		t.Fatalf("GetIMDADashboard: %v", err)
	}

	var got int32
	for _, d := range dash.GetDimensions() {
		if d.GetDimension() == governancev1.IMDADimension_IMDA_DIMENSION_TRANSPARENCY {
			got = d.GetScore()
		}
	}
	if got != score {
		t.Errorf("dashboard transparency score = %d; want %d (Record → Dashboard contract broken)", got, score)
	}
}
