// Package grpcadapter exposes the chora-governance Governance gRPC server.
//
// Source-of-truth: chora-contracts/proto/services/governance/v1/governance.proto.
// Closes the systemic ADR-140 violation tracked in
// docs/m13/grpc-mass-remediation-2026-05-16.md (Wave-1 G-FULL):
// chora-gateway BFF was dialling chora-governance over plain HTTP :8080;
// post-cutover the BFF dials this gRPC server on :9090 instead.
//
// Hexagonal-discipline: this adapter holds no business logic. Each RPC
// delegates to the matching domain port (policy / audit / imda / gatekeeper
// / compliance) and translates between the proto wire format and the
// canonical domain types.
//
// Per `feedback_no_stubs_real_wiring`: server registers unconditionally.
// If a domain dep is nil at construction we fail loud via panic — same
// fail-loud discipline as the HTTP router under the in-memory fallback.
package grpcadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// GovernanceServer implements governancev1.GovernanceServer.
type GovernanceServer struct {
	governancev1.UnimplementedGovernanceServer

	policies  policy.Repository
	audits    audit.Repository
	imdas     imda.Repository
	evaluator *gatekeeper.Evaluator
	generator *compliance.Generator
}

// NewGovernanceServer constructs the gRPC adapter.
func NewGovernanceServer(
	policies policy.Repository,
	audits audit.Repository,
	imdas imda.Repository,
	evaluator *gatekeeper.Evaluator,
	generator *compliance.Generator,
) *GovernanceServer {
	if policies == nil || audits == nil || imdas == nil || evaluator == nil || generator == nil {
		panic("grpcadapter.NewGovernanceServer: all domain ports must be non-nil")
	}
	return &GovernanceServer{
		policies:  policies,
		audits:    audits,
		imdas:     imdas,
		evaluator: evaluator,
		generator: generator,
	}
}

// CreatePolicy
func (s *GovernanceServer) CreatePolicy(ctx context.Context, req *governancev1.CreatePolicyRequest) (*governancev1.CreatePolicyResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	tenantID := req.GetTenantId()
	if req.GetGlobal() {
		tenantID = ""
	}
	conds, err := conditionsFromProto(req.GetConditions())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	rule, err := policy.New(policy.NewParams{
		Name:            req.GetName(),
		TenantID:        tenantID,
		EnforcementMode: enforcementFromProto(req.GetEnforcementMode()),
		Conditions:      conds,
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.policies.Save(ctx, rule); err != nil {
		return nil, status.Errorf(codes.Internal, "save policy: %v", err)
	}
	return &governancev1.CreatePolicyResponse{Rule: ruleToProto(rule)}, nil
}

// GetPolicy
func (s *GovernanceServer) GetPolicy(ctx context.Context, req *governancev1.GetPolicyRequest) (*governancev1.GetPolicyResponse, error) {
	if req == nil || strings.TrimSpace(req.GetRuleId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "rule_id is required")
	}
	rule, err := s.policies.Get(ctx, req.GetRuleId())
	if err != nil {
		if errors.Is(err, policy.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "policy rule not found")
		}
		return nil, status.Errorf(codes.Internal, "get policy: %v", err)
	}
	return &governancev1.GetPolicyResponse{Rule: ruleToProto(rule)}, nil
}

// ListPolicies
func (s *GovernanceServer) ListPolicies(ctx context.Context, req *governancev1.ListPoliciesRequest) (*governancev1.ListPoliciesResponse, error) {
	if req == nil {
		req = &governancev1.ListPoliciesRequest{}
	}
	filter := policy.ListFilter{
		TenantID: req.GetTenantId(),
		Limit:    int(req.GetLimit()),
		Offset:   int(req.GetOffset()),
	}
	rules, err := s.policies.List(ctx, filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list policies: %v", err)
	}
	out := make([]*governancev1.PolicyRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, ruleToProto(r))
	}
	return &governancev1.ListPoliciesResponse{
		Rules: out,
		Total: int32(len(rules)),
	}, nil
}

// Evaluate
func (s *GovernanceServer) Evaluate(ctx context.Context, req *governancev1.EvaluateRequest) (*governancev1.EvaluateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	gctx := contextFromProto(req.GetContext())
	d, err := s.evaluator.Evaluate(ctx, gatekeeper.Request{
		TenantID:    req.GetTenantId(),
		Gcid:        req.GetGcid(),
		Agid:        req.GetAgid(),
		Action:      req.GetAction(),
		Resource:    req.GetResource(),
		Context:     gctx,
		Traceparent: req.GetTraceparent(),
		Tracestate:  req.GetTracestate(),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	matched := make([]*governancev1.PolicyRule, 0, len(d.MatchedRules))
	for _, r := range d.MatchedRules {
		matched = append(matched, ruleToProto(r))
	}
	return &governancev1.EvaluateResponse{
		Decision:     decisionToProto(d.Decision),
		Warned:       d.Warned,
		Reason:       d.Reason,
		MatchedRules: matched,
		AuditEventId: d.AuditEventID,
	}, nil
}

// QueryAuditEvents
func (s *GovernanceServer) QueryAuditEvents(ctx context.Context, req *governancev1.QueryAuditEventsRequest) (*governancev1.QueryAuditEventsResponse, error) {
	if req == nil || strings.TrimSpace(req.GetTenantId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	filter := audit.QueryFilter{
		TenantID:    req.GetTenantId(),
		SubjectType: req.GetSubjectType(),
		SubjectID:   req.GetSubjectId(),
		Limit:       int(req.GetLimit()),
		Offset:      int(req.GetOffset()),
		Cursor:      req.GetCursor(),
	}
	if t := req.GetFrom(); t != nil {
		ts := t.AsTime()
		filter.From = &ts
	}
	if t := req.GetTo(); t != nil {
		ts := t.AsTime()
		filter.To = &ts
	}
	events, err := s.audits.Query(ctx, filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query audit: %v", err)
	}
	out := make([]*governancev1.AuditEvent, 0, len(events))
	for _, e := range events {
		out = append(out, auditToProto(e))
	}
	return &governancev1.QueryAuditEventsResponse{
		Events: out,
		Total:  int32(len(events)),
	}, nil
}

// RecordAssessment
func (s *GovernanceServer) RecordAssessment(ctx context.Context, req *governancev1.RecordAssessmentRequest) (*governancev1.RecordAssessmentResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	a, err := imda.New(imda.NewParams{
		TenantID:     req.GetTenantId(),
		Dimension:    dimensionFromProto(req.GetDimension()),
		Score:        int(req.GetScore()),
		Indicators:   req.GetIndicators(),
		AssessorGcid: req.GetAssessorGcid(),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.imdas.Append(ctx, a); err != nil {
		return nil, status.Errorf(codes.Internal, "append assessment: %v", err)
	}
	return &governancev1.RecordAssessmentResponse{Assessment: assessmentToProto(a)}, nil
}

// GetIMDADashboard
func (s *GovernanceServer) GetIMDADashboard(ctx context.Context, req *governancev1.GetIMDADashboardRequest) (*governancev1.GetIMDADashboardResponse, error) {
	if req == nil || strings.TrimSpace(req.GetTenantId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	dash, err := s.imdas.Dashboard(ctx, req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "dashboard: %v", err)
	}
	out := make([]*governancev1.IMDADimensionAssessment, 0, len(dash))
	for _, a := range dash {
		out = append(out, assessmentToProto(a))
	}
	return &governancev1.GetIMDADashboardResponse{
		TenantId:   req.GetTenantId(),
		Dimensions: out,
	}, nil
}

// GenerateComplianceReport
func (s *GovernanceServer) GenerateComplianceReport(ctx context.Context, req *governancev1.GenerateComplianceReportRequest) (*governancev1.GenerateComplianceReportResponse, error) {
	if req == nil || strings.TrimSpace(req.GetTenantId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	report, err := s.generator.Generate(ctx, req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate report: %v", err)
	}
	return &governancev1.GenerateComplianceReportResponse{Report: reportToProto(report)}, nil
}

// =============================================================================
// proto <-> domain converters
// =============================================================================

func enforcementFromProto(p governancev1.PolicyEnforcementMode) policy.EnforcementMode {
	switch p {
	case governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_ALLOW:
		return policy.ModeAllow
	case governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_WARN:
		return policy.ModeWarn
	case governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_DENY:
		return policy.ModeDeny
	}
	return policy.EnforcementMode("")
}

func enforcementToProto(m policy.EnforcementMode) governancev1.PolicyEnforcementMode {
	switch m {
	case policy.ModeAllow:
		return governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_ALLOW
	case policy.ModeWarn:
		return governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_WARN
	case policy.ModeDeny:
		return governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_DENY
	}
	return governancev1.PolicyEnforcementMode_POLICY_ENFORCEMENT_MODE_UNSPECIFIED
}

func statusToProto(s policy.Status) governancev1.PolicyStatus {
	switch s {
	case policy.StatusActive:
		return governancev1.PolicyStatus_POLICY_STATUS_ACTIVE
	case policy.StatusInactive:
		return governancev1.PolicyStatus_POLICY_STATUS_INACTIVE
	}
	return governancev1.PolicyStatus_POLICY_STATUS_UNSPECIFIED
}

func opFromProto(p governancev1.PolicyConditionOp) policy.Op {
	switch p {
	case governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS:
		return policy.OpEquals
	case governancev1.PolicyConditionOp_POLICY_CONDITION_OP_NOT_EQUALS:
		return policy.OpNotEquals
	case governancev1.PolicyConditionOp_POLICY_CONDITION_OP_IN:
		return policy.OpIn
	}
	return policy.Op("")
}

func opToProto(o policy.Op) governancev1.PolicyConditionOp {
	switch o {
	case policy.OpEquals:
		return governancev1.PolicyConditionOp_POLICY_CONDITION_OP_EQUALS
	case policy.OpNotEquals:
		return governancev1.PolicyConditionOp_POLICY_CONDITION_OP_NOT_EQUALS
	case policy.OpIn:
		return governancev1.PolicyConditionOp_POLICY_CONDITION_OP_IN
	}
	return governancev1.PolicyConditionOp_POLICY_CONDITION_OP_UNSPECIFIED
}

func conditionsFromProto(in []*governancev1.PolicyCondition) ([]policy.Condition, error) {
	out := make([]policy.Condition, 0, len(in))
	for i, c := range in {
		if c == nil {
			return nil, fmt.Errorf("condition[%d] is nil", i)
		}
		out = append(out, policy.Condition{
			Field: c.GetField(),
			Op:    opFromProto(c.GetOp()),
			Value: valueFromProto(c.GetValue()),
		})
	}
	return out, nil
}

func conditionsToProto(in []policy.Condition) []*governancev1.PolicyCondition {
	out := make([]*governancev1.PolicyCondition, 0, len(in))
	for _, c := range in {
		out = append(out, &governancev1.PolicyCondition{
			Field: c.Field,
			Op:    opToProto(c.Op),
			Value: valueToProto(c.Value),
		})
	}
	return out
}

func ruleToProto(r *policy.Rule) *governancev1.PolicyRule {
	if r == nil {
		return nil
	}
	return &governancev1.PolicyRule{
		RuleId:          r.RuleID,
		Name:            r.Name,
		TenantId:        r.TenantID,
		EnforcementMode: enforcementToProto(r.EnforcementMode),
		Conditions:      conditionsToProto(r.Conditions),
		Version:         int32(r.Version),
		Status:          statusToProto(r.Status),
		CreatedAt:       timestamppb.New(r.CreatedAt),
		UpdatedAt:       timestamppb.New(r.UpdatedAt),
	}
}

func decisionToProto(d audit.Decision) governancev1.AuditDecision {
	switch d {
	case audit.DecisionPermitted:
		return governancev1.AuditDecision_AUDIT_DECISION_PERMITTED
	case audit.DecisionDenied:
		return governancev1.AuditDecision_AUDIT_DECISION_DENIED
	}
	return governancev1.AuditDecision_AUDIT_DECISION_UNSPECIFIED
}

func dimensionFromProto(d governancev1.IMDADimension) imda.Dimension {
	switch d {
	case governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY:
		return imda.DimensionRiskLevels
	case governancev1.IMDADimension_IMDA_DIMENSION_TRANSPARENCY:
		return imda.DimensionStakeholderInteraction
	case governancev1.IMDADimension_IMDA_DIMENSION_SAFETY_AND_ROBUSTNESS:
		return imda.DimensionInternalGovernance
	case governancev1.IMDADimension_IMDA_DIMENSION_FAIRNESS_AND_HUMAN_OVERSIGHT:
		return imda.DimensionOperationsManagement
	}
	return imda.Dimension("")
}

func dimensionToProto(d imda.Dimension) governancev1.IMDADimension {
	switch imda.Canonicalise(string(d)) {
	case imda.DimensionRiskLevels:
		return governancev1.IMDADimension_IMDA_DIMENSION_ACCOUNTABILITY
	case imda.DimensionStakeholderInteraction:
		return governancev1.IMDADimension_IMDA_DIMENSION_TRANSPARENCY
	case imda.DimensionInternalGovernance:
		return governancev1.IMDADimension_IMDA_DIMENSION_SAFETY_AND_ROBUSTNESS
	case imda.DimensionOperationsManagement:
		return governancev1.IMDADimension_IMDA_DIMENSION_FAIRNESS_AND_HUMAN_OVERSIGHT
	}
	return governancev1.IMDADimension_IMDA_DIMENSION_UNSPECIFIED
}

func assessmentToProto(a *imda.Assessment) *governancev1.IMDADimensionAssessment {
	if a == nil {
		return nil
	}
	var ts *timestamppb.Timestamp
	if !a.AssessedAt.IsZero() {
		ts = timestamppb.New(a.AssessedAt)
	}
	return &governancev1.IMDADimensionAssessment{
		AssessmentId: a.AssessmentID,
		TenantId:     a.TenantID,
		Dimension:    dimensionToProto(a.Dimension),
		Score:        int32(a.Score),
		Indicators:   append([]string(nil), a.Indicators...),
		AssessedAt:   ts,
		AssessorGcid: a.AssessorGcid,
	}
}

func auditToProto(e *audit.Event) *governancev1.AuditEvent {
	if e == nil {
		return nil
	}
	return &governancev1.AuditEvent{
		EventId:     e.EventID,
		TenantId:    e.TenantID,
		Gcid:        e.Gcid,
		Agid:        e.Agid,
		Action:      e.Action,
		Resource:    e.Resource,
		Decision:    decisionToProto(e.Decision),
		Reason:      e.Reason,
		SubjectType: e.SubjectType,
		SubjectId:   e.SubjectID,
		ActorGcid:   e.ActorGcid,
		Before:      e.Before,
		After:       e.After,
		Traceparent: e.Traceparent,
		Tracestate:  e.Tracestate,
		CreatedAt:   timestamppb.New(e.CreatedAt),
		PrevHash:    e.PrevHash,
		EntryHash:   e.EntryHash,
	}
}

func reportToProto(r *compliance.Report) *governancev1.ComplianceReport {
	if r == nil {
		return nil
	}
	dash := make([]*governancev1.IMDADimensionAssessment, 0, len(r.IMDADashboard))
	for _, a := range r.IMDADashboard {
		dash = append(dash, assessmentToProto(a))
	}
	rec := make([]*governancev1.AuditEvent, 0, len(r.RecentAudits))
	for _, e := range r.RecentAudits {
		rec = append(rec, auditToProto(e))
	}
	return &governancev1.ComplianceReport{
		ReportId:         r.ReportID,
		TenantId:         r.TenantID,
		GeneratedAt:      timestamppb.New(r.GeneratedAt),
		AuditEventCount:  int32(r.AuditEventCount),
		AuditDeniedCount: int32(r.AuditDeniedCount),
		ImdaDashboard:    dash,
		RecentAudits:     rec,
	}
}

func valueFromProto(v *structpb.Value) any {
	if v == nil {
		return nil
	}
	return v.AsInterface()
}

func valueToProto(v any) *structpb.Value {
	if v == nil {
		return structpb.NewNullValue()
	}
	if pv, err := structpb.NewValue(v); err == nil {
		return pv
	}
	b, err := json.Marshal(v)
	if err != nil {
		return structpb.NewStringValue(fmt.Sprintf("%v", v))
	}
	pv := &structpb.Value{}
	if err := pv.UnmarshalJSON(b); err == nil {
		return pv
	}
	return structpb.NewStringValue(fmt.Sprintf("%v", v))
}

func contextFromProto(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

var _ = time.Now
