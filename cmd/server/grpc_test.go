// grpc_test.go — in-process gRPC integration test for the chora-governance
// Governance service. Boots an in-process *grpc.Server with the canonical
// registration (Health + Governance), dials it via bufconn, and exercises
// representative RPCs end-to-end.
//
// Wave-1 G-FULL TDD per docs/m13/grpc-mass-remediation-2026-05-16.md §3.e
// — RED → GREEN gate for the gRPC server registration that lands in
// main.go's `registerGovernanceGRPC` helper. This file lives in
// `package main` so it touches the SAME registration code-path the prod
// entrypoint takes.
package main

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/compliance"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

const bufconnSize = 1024 * 1024

// startBufconnGovernanceServer mirrors the exact registration cmd/server/main.go
// applies on :9090 — Health + Governance. Returns a client conn + cleanup.
func startBufconnGovernanceServer(t *testing.T) (*grpc.ClientConn, func()) {
	t.Helper()

	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	eval := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	gen := compliance.NewGenerator(auditRepo, imdaRepo)

	lis := bufconn.Listen(bufconnSize)
	srv := grpc.NewServer()

	registerGovernanceGRPC(srv, policyRepo, auditRepo, imdaRepo, eval, gen)

	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("bufconn governance server stopped: %v", err)
		}
	}()

	//nolint:staticcheck // bufconn dial requires the legacy DialContext API.
	conn, err := grpc.DialContext(
		context.Background(),
		"bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("bufconn dial: %v", err)
	}

	cleanup := func() {
		_ = conn.Close()
		srv.GracefulStop()
		_ = lis.Close()
	}
	return conn, cleanup
}

// TestBufconn_HealthCheck verifies the gRPC health server is registered and
// returns SERVING — required by Cloud Service Mesh probe routing.
func TestBufconn_HealthCheck(t *testing.T) {
	t.Parallel()
	conn, cleanup := startBufconnGovernanceServer(t)
	defer cleanup()

	hc := healthpb.NewHealthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("Health/Check: %v", err)
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("Health/Check status = %v; want SERVING", resp.GetStatus())
	}
}

// TestBufconn_GetIMDADashboard_Empty exercises the primary BFF call path —
// GetIMDADashboard for a tenant with no assessments. The phase-6 path
// /governance/{tenant_id} that chora-gateway HTTPUpstream.GetGovernance
// dials maps to THIS RPC on the gRPC wire.
func TestBufconn_GetIMDADashboard_Empty(t *testing.T) {
	t.Parallel()
	conn, cleanup := startBufconnGovernanceServer(t)
	defer cleanup()

	client := governancev1.NewGovernanceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.GetIMDADashboard(ctx, &governancev1.GetIMDADashboardRequest{
		TenantId: "01970000-0000-7000-8000-000000000001",
	})
	if err != nil {
		t.Fatalf("GetIMDADashboard: %v", err)
	}
	if resp.GetTenantId() == "" {
		t.Errorf("tenant_id echo was empty")
	}
	if got := len(resp.GetDimensions()); got != 4 {
		t.Errorf("dimensions count = %d; want 4", got)
	}
}

// TestBufconn_RecordAssessment_RoundTrip writes an assessment + reads it via
// the dashboard. Exercises the domain Canonicalise() path indirectly (the
// proto enum maps to the canonical label).
func TestBufconn_RecordAssessment_RoundTrip(t *testing.T) {
	t.Parallel()
	conn, cleanup := startBufconnGovernanceServer(t)
	defer cleanup()

	client := governancev1.NewGovernanceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tenantID := "01970000-0000-7000-8000-000000000002"
	rec, err := client.RecordAssessment(ctx, &governancev1.RecordAssessmentRequest{
		TenantId:     tenantID,
		Dimension:    governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY,
		Score:        85,
		Indicators:   []string{"audit-trail-complete"},
		AssessorGcid: "01970000-0000-7000-9000-000000000010",
	})
	if err != nil {
		t.Fatalf("RecordAssessment: %v", err)
	}
	if rec.GetAssessment().GetScore() != 85 {
		t.Errorf("score = %d; want 85", rec.GetAssessment().GetScore())
	}
	if rec.GetAssessment().GetDimension() != governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY {
		t.Errorf("dimension echo = %v", rec.GetAssessment().GetDimension())
	}

	dash, err := client.GetIMDADashboard(ctx, &governancev1.GetIMDADashboardRequest{TenantId: tenantID})
	if err != nil {
		t.Fatalf("GetIMDADashboard after record: %v", err)
	}
	var got int32
	for _, a := range dash.GetDimensions() {
		if a.GetDimension() == governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY {
			got = a.GetScore()
		}
	}
	if got != 85 {
		t.Errorf("dashboard accountability score = %d; want 85", got)
	}
}

// TestBufconn_Evaluate_DefaultAllow exercises the synchronous Gatekeeper
// path used as a pre-LLM gate from the AI Kernel. With no policies the
// default-allow + audit-emission contract must hold.
func TestBufconn_Evaluate_DefaultAllow(t *testing.T) {
	t.Parallel()
	conn, cleanup := startBufconnGovernanceServer(t)
	defer cleanup()

	client := governancev1.NewGovernanceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.Evaluate(ctx, &governancev1.EvaluateRequest{
		TenantId: "01970000-0000-7000-8000-000000000003",
		Gcid:     "01970000-0000-7000-9000-000000000011",
		Action:   "atom.publish",
		Resource: "atom:abc",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if resp.GetDecision() != governancev1.AuditDecision_AUDIT_DECISION_PERMITTED {
		t.Errorf("decision = %v; want PERMITTED (default-allow)", resp.GetDecision())
	}
	if resp.GetAuditEventId() == "" {
		t.Errorf("audit_event_id empty — every Evaluate MUST emit an AuditEvent")
	}
}
