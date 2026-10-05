// Package gatekeeper is the Gatekeeper domain service of the Governance
// domain.
//
// Behaviour:
//   - Evaluate(req) selects applicable PolicyRules (tenant + global, active
//     only), filters by which rules MATCH the request, and computes a Decision.
//   - DENY OVERRIDES ALLOW: if any matched rule is enforcement_mode=deny, the
//     decision is DENIED regardless of insertion order or count of allow/warn
//     rules.
//   - WARN: if no deny matched but at least one warn matched, decision is
//     PERMITTED but Warned=true.
//   - Default: with no matched rules, permit + audit (default-allow).
//   - Always emits an AuditEvent (allow OR deny).
package gatekeeper

import (
	"context"
	"errors"
	"strings"

	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

// -----------------------------------------------------------------------------
// Request / Decision
// -----------------------------------------------------------------------------

// Request is the input to Evaluate.
type Request struct {
	TenantID    string
	Gcid        string
	Agid        string
	Action      string
	Resource    string
	Context     map[string]any
	Traceparent string
	Tracestate  string
}

// Decision is the output of Evaluate.
type Decision struct {
	Decision     audit.Decision `json:"decision"`
	Warned       bool           `json:"warned,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	MatchedRules []*policy.Rule `json:"matched_rules"`
	AuditEventID string         `json:"audit_event_id"`
}

// -----------------------------------------------------------------------------
// Evaluator
// -----------------------------------------------------------------------------

// Evaluator orchestrates policy evaluation + auditing.
type Evaluator struct {
	policies policy.Repository
	audits   audit.Repository
}

// NewEvaluator wires deps.
func NewEvaluator(p policy.Repository, a audit.Repository) *Evaluator {
	return &Evaluator{policies: p, audits: a}
}

// Evaluate computes a Decision for req. Always emits an AuditEvent — even on
// permit (per spec: allow OR deny — both audited).
func (e *Evaluator) Evaluate(ctx context.Context, req Request) (*Decision, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errors.New("tenant_id is required")
	}
	if strings.TrimSpace(req.Gcid) == "" {
		return nil, errors.New("gcid is required")
	}
	if strings.TrimSpace(req.Action) == "" {
		return nil, errors.New("action is required")
	}

	applicable, err := e.policies.FindApplicable(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}

	// Build the evaluation context map. Caller-provided fields take precedence,
	// but action / resource / tenant_id / gcid are always included.
	evalCtx := make(map[string]any, 8)
	for k, v := range req.Context {
		evalCtx[k] = v
	}
	evalCtx["action"] = req.Action
	evalCtx["resource"] = req.Resource
	evalCtx["tenant_id"] = req.TenantID
	evalCtx["gcid"] = req.Gcid

	matched := make([]*policy.Rule, 0)
	hasDeny := false
	hasWarn := false
	for _, r := range applicable {
		if r.Status != policy.StatusActive {
			continue
		}
		if r.Matches(evalCtx) {
			matched = append(matched, r)
			switch r.EnforcementMode {
			case policy.ModeDeny:
				hasDeny = true
			case policy.ModeWarn:
				hasWarn = true
			}
		}
	}

	decision := audit.DecisionPermitted
	reason := "default-allow: no matched rules"
	if hasDeny {
		decision = audit.DecisionDenied
		reason = "deny rule matched"
	} else if hasWarn {
		reason = "permitted with warning"
	} else if len(matched) > 0 {
		reason = "allow rule matched"
	}

	ev, err := audit.New(audit.NewParams{
		TenantID:    req.TenantID,
		Gcid:        req.Gcid,
		Agid:        req.Agid,
		Action:      req.Action,
		Resource:    req.Resource,
		Decision:    decision,
		Reason:      reason,
		Traceparent: req.Traceparent,
		Tracestate:  req.Tracestate,
	})
	if err != nil {
		return nil, err
	}
	if err := e.audits.Append(ctx, ev); err != nil {
		return nil, err
	}

	return &Decision{
		Decision:     decision,
		Warned:       hasWarn && !hasDeny,
		Reason:       reason,
		MatchedRules: matched,
		AuditEventID: ev.EventID,
	}, nil
}
