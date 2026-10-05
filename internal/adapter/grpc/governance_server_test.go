// governance_server_test.go — unit tests for the Governance gRPC adapter.
//
// Exercises every RPC + every proto<->domain converter in
// internal/adapter/grpc. Written as an INTERNAL test (package grpcadapter)
// so the unexported converter helpers in the second half of the file can be
// driven at table level; the RPCs are driven directly on the server struct
// (no bufconn — the handlers are plain context methods).
//
// Domain ports are the canonical in-memory repositories from the domain
// packages (same fixtures the cmd/server bufconn test uses); error paths use
// small repo wrappers that fail one method.
package grpcadapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	governancev1 "github.com/apollo-chora/chora-contracts/gen/go/chora/services/governance/v1"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/compliance"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

// -----------------------------------------------------------------------------
// server construction
// -----------------------------------------------------------------------------

func newTestServer(t *testing.T) (*GovernanceServer, *policy.InMemoryRepository, *audit.InMemoryRepository, *imda.InMemoryRepository) {
	t.Helper()
	policyRepo := policy.NewInMemoryRepository()
	auditRepo := audit.NewInMemoryRepository()
	imdaRepo := imda.NewInMemoryRepository()
	eval := gatekeeper.NewEvaluator(policyRepo, auditRepo)
	gen := compliance.NewGenerator(auditRepo, imdaRepo)
	srv := NewGovernanceServer(policyRepo, auditRepo, imdaRepo, eval, gen)
	return srv, policyRepo, auditRepo, imdaRepo
}

func TestNewGovernanceServer_RejectsNilDeps(t *testing.T) {
	t.Parallel()
	p := policy.NewInMemoryRepository()
	a := audit.NewInMemoryRepository()
	i := imda.NewInMemoryRepository()
	e := gatekeeper.NewEvaluator(p, a)
	g := compliance.NewGenerator(a, i)

	cases := []struct {
		name      string
		policies  policy.Repository
		audits    audit.Repository
		imdas     imda.Repository
		evaluator *gatekeeper.Evaluator
		generator *compliance.Generator
	}{
		{name: "nil policies", policies: nil, audits: a, imdas: i, evaluator: e, generator: g},
		{name: "nil audits", policies: p, audits: nil, imdas: i, evaluator: e, generator: g},
		{name: "nil imdas", policies: p, audits: a, imdas: nil, evaluator: e, generator: g},
		{name: "nil evaluator", policies: p, audits: a, imdas: i, evaluator: nil, generator: g},
		{name: "nil generator", policies: p, audits: a, imdas: i, evaluator: e, generator: nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("NewGovernanceServer(%s): expected panic", tc.name)
				}
			}()
			NewGovernanceServer(tc.policies, tc.audits, tc.imdas, tc.evaluator, tc.generator)
		})
	}
}

// -----------------------------------------------------------------------------
// policy RPCs
// -----------------------------------------------------------------------------

func TestCreatePolicy_SuccessAndGlobal(t *testing.T) {
	t.Parallel()
	srv, repo, _, _ := newTestServer(t)
	ctx := context.Background()

	resp, err := srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
		Name:            "deny-exfil",
		TenantId:        "tenant-1",
		EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_DENY,
		Conditions: []*governancev1.PolicyCondition{
			{Field: "action", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, Value: structpb.NewStringValue("exfil")},
			{Field: "resource", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_IN, Value: structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("a"), structpb.NewStringValue("b")}})},
			{Field: "gcid", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_NOT_EQUALS, Value: structpb.NewStringValue("root")},
		},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if resp.GetRule().GetRuleId() == "" {
		t.Error("rule_id is empty")
	}
	if resp.GetRule().GetTenantId() != "tenant-1" {
		t.Errorf("TenantId = %q; want tenant-1", resp.GetRule().GetTenantId())
	}
	if resp.GetRule().GetEnforcementMode() != governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_DENY {
		t.Errorf("EnforcementMode = %v; want DENY", resp.GetRule().GetEnforcementMode())
	}
	got, err := repo.Get(ctx, resp.GetRule().GetRuleId())
	if err != nil {
		t.Fatalf("repo.Get: %v", err)
	}
	if got.Name != "deny-exfil" || len(got.Conditions) != 3 {
		t.Errorf("persisted rule mismatch: name=%q conds=%d", got.Name, len(got.Conditions))
	}

	// Global rule — tenant_id must be blanked.
	gresp, err := srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
		Name:            "global-alert",
		TenantId:        "tenant-9",
		Global:          true,
		EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_WARN,
		Conditions: []*governancev1.PolicyCondition{
			{Field: "action", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, Value: structpb.NewStringValue("report")},
		},
	})
	if err != nil {
		t.Fatalf("CreatePolicy(global): %v", err)
	}
	if gresp.GetRule().GetTenantId() != "" {
		t.Errorf("global rule TenantId = %q; want empty", gresp.GetRule().GetTenantId())
	}
}

func TestCreatePolicy_Errors(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	if _, err := srv.CreatePolicy(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil req: got %v; want InvalidArgument", err)
	}

	// nil condition inside the list
	_, err := srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
		Name:            "bad",
		EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_ALLOW,
		Conditions:      []*governancev1.PolicyCondition{nil},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil condition: got %v; want InvalidArgument", err)
	}

	// invalid enforcement mode
	_, err = srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
		Name:            "bad-mode",
		EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_UNSPECIFIED,
		Conditions: []*governancev1.PolicyCondition{
			{Field: "action", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, Value: structpb.NewStringValue("x")},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("invalid mode: got %v; want InvalidArgument", err)
	}
}

func TestCreatePolicy_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pr := &failingPolicyRepo{InMemoryRepository: policy.NewInMemoryRepository(), errOnSave: true}
	srv := NewGovernanceServer(pr, audit.NewInMemoryRepository(), imda.NewInMemoryRepository(),
		gatekeeper.NewEvaluator(pr, audit.NewInMemoryRepository()), compliance.NewGenerator(audit.NewInMemoryRepository(), imda.NewInMemoryRepository()))
	_, err := srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
		Name:            "x",
		EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_ALLOW,
		Conditions:      []*governancev1.PolicyCondition{{Field: "action", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, Value: structpb.NewStringValue("x")}},
	})
	if status.Code(err) != codes.Internal {
		t.Errorf("repo error: got %v; want Internal", err)
	}
}

func TestGetPolicy_RoundTripAndErrors(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	created, err := srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
		Name:            "get-me",
		TenantId:        "tenant-1",
		EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_ALLOW,
		Conditions:      []*governancev1.PolicyCondition{{Field: "action", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, Value: structpb.NewStringValue("read")}},
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	got, err := srv.GetPolicy(ctx, &governancev1.GetPolicyRequest{RuleId: created.GetRule().GetRuleId()})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.GetRule().GetName() != "get-me" {
		t.Errorf("Name = %q; want get-me", got.GetRule().GetName())
	}

	if _, err := srv.GetPolicy(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil req: got %v; want InvalidArgument", err)
	}
	if _, err := srv.GetPolicy(ctx, &governancev1.GetPolicyRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty rule_id: got %v; want InvalidArgument", err)
	}
	if _, err := srv.GetPolicy(ctx, &governancev1.GetPolicyRequest{RuleId: "missing"}); status.Code(err) != codes.NotFound {
		t.Errorf("missing rule: got %v; want NotFound", err)
	}
}

func TestGetPolicy_RepoInternalError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ar := audit.NewInMemoryRepository()
	pr := &failingPolicyRepo{InMemoryRepository: policy.NewInMemoryRepository(), errOnGet: true}
	srv := NewGovernanceServer(pr, ar, imda.NewInMemoryRepository(),
		gatekeeper.NewEvaluator(pr, ar), compliance.NewGenerator(ar, imda.NewInMemoryRepository()))
	_, err := srv.GetPolicy(ctx, &governancev1.GetPolicyRequest{RuleId: "r1"})
	if status.Code(err) != codes.Internal {
		t.Errorf("repo error: got %v; want Internal", err)
	}
}

func TestListPolicies_DefaultsNilRequest(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	for _, n := range []string{"a", "b", "c"} {
		if _, err := srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
			Name:            n,
			TenantId:        "tenant-1",
			EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_ALLOW,
			Conditions:      []*governancev1.PolicyCondition{{Field: "action", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, Value: structpb.NewStringValue("read")}},
		}); err != nil {
			t.Fatalf("CreatePolicy(%s): %v", n, err)
		}
	}

	resp, err := srv.ListPolicies(ctx, nil)
	if err != nil {
		t.Fatalf("ListPolicies(nil): %v", err)
	}
	if resp.GetTotal() != 3 || len(resp.GetRules()) != 3 {
		t.Errorf("total = %d len = %d; want 3/3", resp.GetTotal(), len(resp.GetRules()))
	}

	scoped, err := srv.ListPolicies(ctx, &governancev1.ListPoliciesRequest{TenantId: "tenant-1", Limit: 2})
	if err != nil {
		t.Fatalf("ListPolicies(tenant): %v", err)
	}
	if len(scoped.GetRules()) != 2 {
		t.Errorf("limit 2 → %d rules", len(scoped.GetRules()))
	}
}

func TestListPolicies_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ar := audit.NewInMemoryRepository()
	pr := &failingPolicyRepo{InMemoryRepository: policy.NewInMemoryRepository(), errOnList: true}
	srv := NewGovernanceServer(pr, ar, imda.NewInMemoryRepository(),
		gatekeeper.NewEvaluator(pr, ar), compliance.NewGenerator(ar, imda.NewInMemoryRepository()))
	_, err := srv.ListPolicies(ctx, &governancev1.ListPoliciesRequest{TenantId: "t"})
	if status.Code(err) != codes.Internal {
		t.Errorf("repo error: got %v; want Internal", err)
	}
}

// -----------------------------------------------------------------------------
// Evaluate RPC
// -----------------------------------------------------------------------------

func TestEvaluate_PermitAndDeny(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	// allow rule for action=read
	if _, err := srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
		Name:            "allow-read",
		TenantId:        "tenant-1",
		EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_ALLOW,
		Conditions:      []*governancev1.PolicyCondition{{Field: "action", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, Value: structpb.NewStringValue("read")}},
	}); err != nil {
		t.Fatalf("CreatePolicy(allow): %v", err)
	}
	// deny rule for action=write
	if _, err := srv.CreatePolicy(ctx, &governancev1.CreatePolicyRequest{
		Name:            "deny-write",
		TenantId:        "tenant-1",
		EnforcementMode: governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_DENY,
		Conditions:      []*governancev1.PolicyCondition{{Field: "action", Op: governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, Value: structpb.NewStringValue("write")}},
	}); err != nil {
		t.Fatalf("CreatePolicy(deny): %v", err)
	}

	ctxStruct, err := structpb.NewStruct(map[string]any{"region": "sg"})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	permit, err := srv.Evaluate(ctx, &governancev1.EvaluateRequest{
		TenantId: "tenant-1", Gcid: "gcid-1", Action: "read", Resource: "lesson",
		Context: ctxStruct,
	})
	if err != nil {
		t.Fatalf("Evaluate(permit): %v", err)
	}
	if permit.GetDecision() != governancev1.AuditDecision_AUDIT_DECISION_PERMITTED {
		t.Errorf("Decision = %v; want PERMITTED", permit.GetDecision())
	}
	if len(permit.GetMatchedRules()) != 1 {
		t.Errorf("MatchedRules = %d; want 1", len(permit.GetMatchedRules()))
	}
	if permit.GetAuditEventId() == "" {
		t.Error("AuditEventId is empty")
	}

	deny, err := srv.Evaluate(ctx, &governancev1.EvaluateRequest{
		TenantId: "tenant-1", Gcid: "gcid-1", Action: "write", Resource: "lesson",
		Traceparent: "00-abc-def-01", Tracestate: "vendor=1",
	})
	if err != nil {
		t.Fatalf("Evaluate(deny): %v", err)
	}
	if deny.GetDecision() != governancev1.AuditDecision_AUDIT_DECISION_DENIED {
		t.Errorf("Decision = %v; want DENIED", deny.GetDecision())
	}
}

func TestEvaluate_Errors(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	if _, err := srv.Evaluate(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil req: got %v; want InvalidArgument", err)
	}
	// evaluator refuses empty tenant_id
	_, err := srv.Evaluate(ctx, &governancev1.EvaluateRequest{Gcid: "g", Action: "a"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty tenant: got %v; want InvalidArgument", err)
	}
}

// -----------------------------------------------------------------------------
// audit RPCs
// -----------------------------------------------------------------------------

func seedAuditEvents(t *testing.T, repo *audit.InMemoryRepository, tenantID string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ev, err := audit.New(audit.NewParams{
			TenantID: tenantID,
			Gcid:     "gcid-1",
			Action:   "read",
			Resource: "lesson",
			Decision: audit.DecisionPermitted,
		})
		if err != nil {
			t.Fatalf("audit.New: %v", err)
		}
		if err := repo.Append(context.Background(), ev); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
}

func TestQueryAuditEvents_RangeAndPaging(t *testing.T) {
	t.Parallel()
	srv, _, auditRepo, _ := newTestServer(t)
	ctx := context.Background()
	seedAuditEvents(t, auditRepo, "tenant-1", 3)

	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)
	resp, err := srv.QueryAuditEvents(ctx, &governancev1.QueryAuditEventsRequest{
		TenantId: "tenant-1",
		From:     timestamppb.New(from),
		To:       timestamppb.New(to),
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("QueryAuditEvents: %v", err)
	}
	if resp.GetTotal() != 2 {
		t.Errorf("Total = %d; want 2 (server reports returned count after limit)", resp.GetTotal())
	}
	if len(resp.GetEvents()) != 2 {
		t.Errorf("Limit 2 → %d events", len(resp.GetEvents()))
	}
	if resp.GetEvents()[0].GetCreatedAt() == nil {
		t.Error("event CreatedAt missing")
	}
}

func TestQueryAuditEvents_Errors(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	if _, err := srv.QueryAuditEvents(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil req: got %v; want InvalidArgument", err)
	}
	if _, err := srv.QueryAuditEvents(ctx, &governancev1.QueryAuditEventsRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty tenant: got %v; want InvalidArgument", err)
	}
}

func TestQueryAuditEvents_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ar := &failingAuditRepo{InMemoryRepository: audit.NewInMemoryRepository(), errOnQuery: true}
	pr := policy.NewInMemoryRepository()
	srv := NewGovernanceServer(pr, ar, imda.NewInMemoryRepository(),
		gatekeeper.NewEvaluator(pr, ar), compliance.NewGenerator(ar, imda.NewInMemoryRepository()))
	_, err := srv.QueryAuditEvents(ctx, &governancev1.QueryAuditEventsRequest{TenantId: "t"})
	if status.Code(err) != codes.Internal {
		t.Errorf("repo error: got %v; want Internal", err)
	}
}

// -----------------------------------------------------------------------------
// IMDA RPCs
// -----------------------------------------------------------------------------

func TestRecordAssessment_RoundTrip(t *testing.T) {
	t.Parallel()
	srv, _, _, imdaRepo := newTestServer(t)
	ctx := context.Background()

	resp, err := srv.RecordAssessment(ctx, &governancev1.RecordAssessmentRequest{
		TenantId:     "tenant-1",
		Dimension:    governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY,
		Score:        85,
		Indicators:   []string{"logs", "trace"},
		AssessorGcid: "gcid-1",
	})
	if err != nil {
		t.Fatalf("RecordAssessment: %v", err)
	}
	if resp.GetAssessment().GetAssessmentId() == "" {
		t.Error("assessment_id is empty")
	}
	if resp.GetAssessment().GetDimension() != governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY {
		t.Errorf("Dimension = %v; want ACCOUNTABILITY", resp.GetAssessment().GetDimension())
	}
	if resp.GetAssessment().GetAssessedAt() == nil {
		t.Error("AssessedAt missing")
	}
	if _, err := imdaRepo.Dashboard(ctx, "tenant-1"); err != nil {
		t.Fatalf("Dashboard: %v", err)
	}
}

func TestRecordAssessment_Errors(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	if _, err := srv.RecordAssessment(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil req: got %v; want InvalidArgument", err)
	}
	// empty tenant → imda.New rejects
	_, err := srv.RecordAssessment(ctx, &governancev1.RecordAssessmentRequest{
		Dimension: governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY,
		Score:     50,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty tenant: got %v; want InvalidArgument", err)
	}
}

func TestRecordAssessment_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ar := audit.NewInMemoryRepository()
	ir := &failingIMDARepo{InMemoryRepository: imda.NewInMemoryRepository(), errOnAppend: true}
	srv := NewGovernanceServer(policy.NewInMemoryRepository(), ar, ir,
		gatekeeper.NewEvaluator(policy.NewInMemoryRepository(), ar), compliance.NewGenerator(ar, ir))
	_, err := srv.RecordAssessment(ctx, &governancev1.RecordAssessmentRequest{
		TenantId:     "t",
		Dimension:    governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY,
		Score:        50,
		AssessorGcid: "gcid-1",
	})
	if status.Code(err) != codes.Internal {
		t.Errorf("repo error: got %v; want Internal", err)
	}
}

func TestGetIMDADashboard_Placeholders(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	resp, err := srv.GetIMDADashboard(ctx, &governancev1.GetIMDADashboardRequest{TenantId: "tenant-1"})
	if err != nil {
		t.Fatalf("GetIMDADashboard: %v", err)
	}
	if resp.GetTenantId() != "tenant-1" {
		t.Errorf("TenantId = %q", resp.GetTenantId())
	}
	// 4 dimensions, all placeholder (score 0, no ID).
	if len(resp.GetDimensions()) != 4 {
		t.Fatalf("Dimensions = %d; want 4", len(resp.GetDimensions()))
	}
	for _, a := range resp.GetDimensions() {
		if a.GetScore() != 0 {
			t.Errorf("placeholder score = %d; want 0", a.GetScore())
		}
	}
}

func TestGetIMDADashboard_Errors(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	if _, err := srv.GetIMDADashboard(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil req: got %v; want InvalidArgument", err)
	}
	if _, err := srv.GetIMDADashboard(ctx, &governancev1.GetIMDADashboardRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty tenant: got %v; want InvalidArgument", err)
	}
}

func TestGetIMDADashboard_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ar := audit.NewInMemoryRepository()
	ir := &failingIMDARepo{InMemoryRepository: imda.NewInMemoryRepository(), errOnDashboard: true}
	srv := NewGovernanceServer(policy.NewInMemoryRepository(), ar, ir,
		gatekeeper.NewEvaluator(policy.NewInMemoryRepository(), ar), compliance.NewGenerator(ar, ir))
	_, err := srv.GetIMDADashboard(ctx, &governancev1.GetIMDADashboardRequest{TenantId: "t"})
	if status.Code(err) != codes.Internal {
		t.Errorf("repo error: got %v; want Internal", err)
	}
}

// -----------------------------------------------------------------------------
// compliance RPC
// -----------------------------------------------------------------------------

func TestGenerateComplianceReport(t *testing.T) {
	t.Parallel()
	srv, _, auditRepo, imdaRepo := newTestServer(t)
	ctx := context.Background()
	seedAuditEvents(t, auditRepo, "tenant-1", 2)

	// one denied event to exercise the denied counter
	denied, err := audit.New(audit.NewParams{TenantID: "tenant-1", Gcid: "g", Action: "write", Decision: audit.DecisionDenied})
	if err != nil {
		t.Fatalf("audit.New(denied): %v", err)
	}
	if err := auditRepo.Append(ctx, denied); err != nil {
		t.Fatalf("Append: %v", err)
	}

	assess, err := imda.New(imda.NewParams{TenantID: "tenant-1", Dimension: imda.DimensionRiskLevels, Score: 90, Indicators: []string{"x"}, AssessorGcid: "gcid-1"})
	if err != nil {
		t.Fatalf("imda.New: %v", err)
	}
	if err := imdaRepo.Append(ctx, assess); err != nil {
		t.Fatalf("imdaRepo.Append: %v", err)
	}

	resp, err := srv.GenerateComplianceReport(ctx, &governancev1.GenerateComplianceReportRequest{TenantId: "tenant-1"})
	if err != nil {
		t.Fatalf("GenerateComplianceReport: %v", err)
	}
	rep := resp.GetReport()
	if rep.GetReportId() == "" {
		t.Error("ReportId empty")
	}
	if rep.GetAuditEventCount() != 3 {
		t.Errorf("AuditEventCount = %d; want 3", rep.GetAuditEventCount())
	}
	if rep.GetAuditDeniedCount() != 1 {
		t.Errorf("AuditDeniedCount = %d; want 1", rep.GetAuditDeniedCount())
	}
	if len(rep.GetImdaDashboard()) != 4 {
		t.Errorf("ImdaDashboard = %d; want 4 (incl. placeholders)", len(rep.GetImdaDashboard()))
	}
	if len(rep.GetRecentAudits()) != 3 {
		t.Errorf("RecentAudits = %d; want 3", len(rep.GetRecentAudits()))
	}
}

func TestGenerateComplianceReport_Errors(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newTestServer(t)
	ctx := context.Background()

	if _, err := srv.GenerateComplianceReport(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Errorf("nil req: got %v; want InvalidArgument", err)
	}
	if _, err := srv.GenerateComplianceReport(ctx, &governancev1.GenerateComplianceReportRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty tenant: got %v; want InvalidArgument", err)
	}
}

func TestGenerateComplianceReport_RepoError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ar := &failingAuditRepo{InMemoryRepository: audit.NewInMemoryRepository(), errOnQuery: true}
	pr := policy.NewInMemoryRepository()
	srv := NewGovernanceServer(pr, ar, imda.NewInMemoryRepository(),
		gatekeeper.NewEvaluator(pr, ar), compliance.NewGenerator(ar, imda.NewInMemoryRepository()))
	_, err := srv.GenerateComplianceReport(ctx, &governancev1.GenerateComplianceReportRequest{TenantId: "t"})
	if status.Code(err) != codes.Internal {
		t.Errorf("repo error: got %v; want Internal", err)
	}
}

// -----------------------------------------------------------------------------
// converters — table tests drive every switch branch
// -----------------------------------------------------------------------------

func TestEnforcementConverters(t *testing.T) {
	t.Parallel()
	cases := []struct {
		proto governancev1.PolicyEnforcementMode
		dom   policy.EnforcementMode
	}{
		{governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_ALLOW, policy.ModeAllow},
		{governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_WARN, policy.ModeWarn},
		{governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_DENY, policy.ModeDeny},
		{governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_UNSPECIFIED, policy.EnforcementMode("")},
	}
	for _, tc := range cases {
		if got := enforcementFromProto(tc.proto); got != tc.dom {
			t.Errorf("enforcementFromProto(%v) = %q; want %q", tc.proto, got, tc.dom)
		}
		if got := enforcementToProto(tc.dom); got != tc.proto {
			t.Errorf("enforcementToProto(%q) = %v; want %v", tc.dom, got, tc.proto)
		}
	}
}

func TestStatusToProto_AllBranches(t *testing.T) {
	t.Parallel()
	if statusToProto(policy.StatusActive) != governancev1.PolicyStatus_POLICY_STATUS_ACTIVE {
		t.Error("StatusActive → ACTIVE")
	}
	if statusToProto(policy.StatusInactive) != governancev1.PolicyStatus_POLICY_STATUS_INACTIVE {
		t.Error("StatusInactive → INACTIVE")
	}
	if statusToProto(policy.Status("bogus")) != governancev1.PolicyStatus_POLICY_STATUS_UNSPECIFIED {
		t.Error("bogus → UNSPECIFIED")
	}
}

func TestOpConverters_AllBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		proto governancev1.PolicyConditionOp
		dom   policy.Op
	}{
		{governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS, policy.OpEquals},
		{governancev1.PolicyConditionOp_POLICY_CONDITION_OP_NOT_EQUALS, policy.OpNotEquals},
		{governancev1.PolicyConditionOp_POLICY_CONDITION_OP_IN, policy.OpIn},
		{governancev1.PolicyConditionOp_POLICY_CONDITION_OP_UNSPECIFIED, policy.Op("")},
	}
	for _, tc := range cases {
		if got := opFromProto(tc.proto); got != tc.dom {
			t.Errorf("opFromProto(%v) = %q; want %q", tc.proto, got, tc.dom)
		}
		if got := opToProto(tc.dom); got != tc.proto {
			t.Errorf("opToProto(%q) = %v; want %v", tc.dom, got, tc.proto)
		}
	}
}

func TestDecisionToProto_AllBranches(t *testing.T) {
	t.Parallel()
	if decisionToProto(audit.DecisionPermitted) != governancev1.AuditDecision_AUDIT_DECISION_PERMITTED {
		t.Error("Permitted → PERMITTED")
	}
	if decisionToProto(audit.DecisionDenied) != governancev1.AuditDecision_AUDIT_DECISION_DENIED {
		t.Error("Denied → DENIED")
	}
	if decisionToProto(audit.Decision("bogus")) != governancev1.AuditDecision_AUDIT_DECISION_UNSPECIFIED {
		t.Error("bogus → UNSPECIFIED")
	}
}

func TestDimensionConverters_AllBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		proto governancev1.IMDADimension
		dom   imda.Dimension
	}{
		{governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY, imda.DimensionRiskLevels},
		{governancev1.IMDADimension_IMDA_DIMENSION_TRANSPARENCY, imda.DimensionStakeholderInteraction},
		{governancev1.IMDADimension_IMDA_DIMENSION_SAFETY_AND_ROBUSTNESS, imda.DimensionInternalGovernance},
		{governancev1.IMDADimension_IMDA_DIMENSION_FAIRNESS_AND_HUMAN_OVERSIGHT, imda.DimensionOperationsManagement},
		{governancev1.IMDADimension_IMDA_DIMENSION_UNSPECIFIED, imda.Dimension("")},
	}
	for _, tc := range cases {
		if got := dimensionFromProto(tc.proto); got != tc.dom {
			t.Errorf("dimensionFromProto(%v) = %q; want %q", tc.proto, got, tc.dom)
		}
		if got := dimensionToProto(tc.dom); got != tc.proto {
			t.Errorf("dimensionToProto(%q) = %v; want %v", tc.dom, got, tc.proto)
		}
	}
}

func TestRuleToProto_NilAndFull(t *testing.T) {
	t.Parallel()
	if ruleToProto(nil) != nil {
		t.Error("ruleToProto(nil) should be nil")
	}
	now := time.Now().UTC()
	r := &policy.Rule{
		RuleID:          "r1",
		Name:            "n",
		TenantID:        "t",
		EnforcementMode: policy.ModeWarn,
		Conditions: []policy.Condition{
			{Field: "action", Op: policy.OpIn, Value: []any{"a", "b"}},
		},
		Version:   2,
		Status:    policy.StatusInactive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	p := ruleToProto(r)
	if p.GetRuleId() != "r1" || p.GetName() != "n" || p.GetVersion() != 2 {
		t.Errorf("ruleToProto mismatch: %+v", p)
	}
	if p.GetStatus() != governancev1.PolicyStatus_POLICY_STATUS_INACTIVE {
		t.Error("status round-trip failed")
	}
	if len(p.GetConditions()) != 1 || p.GetConditions()[0].GetOp() != governancev1.PolicyConditionOp_POLICY_CONDITION_OP_IN {
		t.Error("conditions round-trip failed")
	}
	// static conditionsToProto empty input
	if out := conditionsToProto(nil); len(out) != 0 {
		t.Errorf("conditionsToProto(nil) = %d; want 0", len(out))
	}
}

func TestAssessmentToProto_NilAndZeroTime(t *testing.T) {
	t.Parallel()
	if assessmentToProto(nil) != nil {
		t.Error("assessmentToProto(nil) should be nil")
	}
	zero := &imda.Assessment{AssessmentID: "a1", TenantID: "t", Dimension: imda.DimensionRiskLevels, Score: 42, Indicators: []string{"i"}}
	p := assessmentToProto(zero)
	if p.GetAssessedAt() != nil {
		t.Error("zero AssessedAt should stay nil")
	}
	if got := dimensionToProto(imda.DimensionRiskLevels); got != governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY {
		t.Errorf("dimensionToProto(risk_levels) = %v", got)
	}
}

func TestAuditToProto_NilAndFull(t *testing.T) {
	t.Parallel()
	if auditToProto(nil) != nil {
		t.Error("auditToProto(nil) should be nil")
	}
	now := time.Now().UTC()
	ev := &audit.Event{
		EventID:   "e1",
		TenantID:  "t1",
		Gcid:      "g1",
		Action:    "read",
		Decision:  audit.DecisionDenied,
		CreatedAt: now,
	}
	p := auditToProto(ev)
	if p.GetEventId() != "e1" || p.GetTenantId() != "t1" || p.GetDecision() != governancev1.AuditDecision_AUDIT_DECISION_DENIED {
		t.Errorf("auditToProto mismatch: %+v", p)
	}
	if p.GetCreatedAt() == nil {
		t.Error("CreatedAt missing")
	}
}

func TestReportToProto_NilAndFull(t *testing.T) {
	t.Parallel()
	if reportToProto(nil) != nil {
		t.Error("reportToProto(nil) should be nil")
	}
	now := time.Now().UTC()
	r := &compliance.Report{
		ReportID:         "rep-1",
		TenantID:         "t1",
		GeneratedAt:      now,
		AuditEventCount:  2,
		AuditDeniedCount: 1,
		IMDADashboard: []*imda.Assessment{
			{AssessmentID: "a1", TenantID: "t1", Dimension: imda.DimensionRiskLevels, Score: 10},
		},
		RecentAudits: []*audit.Event{
			{EventID: "e1", TenantID: "t1", Gcid: "g1", Action: "read", Decision: audit.DecisionPermitted, CreatedAt: now},
		},
	}
	p := reportToProto(r)
	if p.GetReportId() != "rep-1" || p.GetAuditEventCount() != 2 || p.GetAuditDeniedCount() != 1 {
		t.Errorf("reportToProto mismatch: %+v", p)
	}
	if len(p.GetImdaDashboard()) != 1 || len(p.GetRecentAudits()) != 1 {
		t.Error("reportToProto nested slices wrong")
	}
}

func TestValueConverters(t *testing.T) {
	t.Parallel()
	if v := valueFromProto(nil); v != nil {
		t.Errorf("valueFromProto(nil) = %v; want nil", v)
	}
	sv := structpb.NewStringValue("hello")
	if v := valueFromProto(sv); v != "hello" {
		t.Errorf("valueFromProto = %v; want hello", v)
	}

	if p := valueToProto(nil); p.GetKind() == nil || p.GetStringValue() != "" {
		t.Errorf("valueToProto(nil) = %v; want null", p)
	}
	if p := valueToProto("plain"); p.GetStringValue() != "plain" {
		t.Errorf("valueToProto(plain): got %v", p)
	}
	if p := valueToProto(map[string]any{"k": "v"}); p.GetStructValue().GetFields()["k"].GetStringValue() != "v" {
		t.Errorf("valueToProto(map): got %v", p)
	}
	// NewValue + json.Marshal both fail → string fallback via fmt.Sprintf.
	if p := valueToProto(func() {}); p.GetStringValue() == "" {
		t.Errorf("valueToProto(func) should fall back to a string value")
	}
	// json.Marshal succeeds but emits JSON that is not a valid structpb value
	// → string fallback via fmt.Sprintf.
	bad := badJSONValue{raw: "not json"}
	if p := valueToProto(bad); p.GetStringValue() != "{not json}" {
		t.Errorf("valueToProto(badJSON) = %v; want fmt.Sprintf fallback", p)
	}
}

// badJSONValue implements json.Marshaler but hands back invalid JSON, forcing
// valueToProto into its UnmarshalJSON-failure fallback branch.
type badJSONValue struct{ raw string }

func (b badJSONValue) MarshalJSON() ([]byte, error) { return []byte(b.raw), nil }

func TestContextFromProto(t *testing.T) {
	t.Parallel()
	if contextFromProto(nil) != nil {
		t.Error("contextFromProto(nil) should be nil")
	}
	s, err := structpb.NewStruct(map[string]any{"a": "b"})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	m := contextFromProto(s)
	if m["a"] != "b" {
		t.Errorf("contextFromProto = %v", m)
	}
}

func TestConditionsFromProto_NilCondition(t *testing.T) {
	t.Parallel()
	if _, err := conditionsFromProto([]*governancev1.PolicyCondition{nil}); err == nil {
		t.Error("nil condition should error")
	}
}

// -----------------------------------------------------------------------------
// helper — repository wrappers that fail a single method
// -----------------------------------------------------------------------------

type failingPolicyRepo struct {
	*policy.InMemoryRepository
	errOnSave       bool
	errOnGet        bool
	errOnList       bool
	errOnApplicable bool
}

func (f *failingPolicyRepo) Save(ctx context.Context, r *policy.Rule) error {
	if f.errOnSave {
		return errors.New("save failed")
	}
	return f.InMemoryRepository.Save(ctx, r)
}

func (f *failingPolicyRepo) Get(ctx context.Context, ruleID string) (*policy.Rule, error) {
	if f.errOnGet {
		return nil, errors.New("get failed")
	}
	return f.InMemoryRepository.Get(ctx, ruleID)
}

func (f *failingPolicyRepo) List(ctx context.Context, filter policy.ListFilter) ([]*policy.Rule, error) {
	if f.errOnList {
		return nil, errors.New("list failed")
	}
	return f.InMemoryRepository.List(ctx, filter)
}

func (f *failingPolicyRepo) FindApplicable(ctx context.Context, tenantID string) ([]*policy.Rule, error) {
	if f.errOnApplicable {
		return nil, errors.New("find failed")
	}
	return f.InMemoryRepository.FindApplicable(ctx, tenantID)
}

type failingAuditRepo struct {
	*audit.InMemoryRepository
	errOnAppend bool
	errOnQuery  bool
}

func (f *failingAuditRepo) Append(ctx context.Context, e *audit.Event) error {
	if f.errOnAppend {
		return errors.New("append failed")
	}
	return f.InMemoryRepository.Append(ctx, e)
}

func (f *failingAuditRepo) Query(ctx context.Context, filter audit.QueryFilter) ([]*audit.Event, error) {
	if f.errOnQuery {
		return nil, errors.New("query failed")
	}
	return f.InMemoryRepository.Query(ctx, filter)
}

type failingIMDARepo struct {
	*imda.InMemoryRepository
	errOnAppend    bool
	errOnDashboard bool
}

func (f *failingIMDARepo) Append(ctx context.Context, a *imda.Assessment) error {
	if f.errOnAppend {
		return errors.New("append failed")
	}
	return f.InMemoryRepository.Append(ctx, a)
}

func (f *failingIMDARepo) Dashboard(ctx context.Context, tenantID string) ([]*imda.Assessment, error) {
	if f.errOnDashboard {
		return nil, errors.New("dashboard failed")
	}
	return f.InMemoryRepository.Dashboard(ctx, tenantID)
}
