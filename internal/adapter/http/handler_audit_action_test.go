package httpadapter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	httpadapter "github.com/apollo-chora/chora-governance/internal/adapter/http"
	"github.com/apollo-chora/chora-governance/internal/domain/audit"
	"github.com/apollo-chora/chora-governance/internal/domain/gatekeeper"
	"github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/policy"
)

// GET /api/audit?action=<discriminator> must scope the response to that action.
// This is the upstream the gateway's /bff/oplus/governance/egress-audit read
// calls to fetch ONLY the external_egress slice (CHO-2245).
func TestAudit_FiltersByActionParam(t *testing.T) {
	t.Parallel()
	auditRepo := audit.NewInMemoryRepository()
	ctx := context.Background()
	seed := func(action string) {
		ev, err := audit.New(audit.NewParams{
			TenantID: tenantA, Gcid: gcidA, Action: action,
			Resource: "r", Decision: audit.DecisionPermitted,
		})
		if err != nil {
			t.Fatalf("seed new: %v", err)
		}
		if err := auditRepo.Append(ctx, ev); err != nil {
			t.Fatalf("seed append: %v", err)
		}
	}
	seed("external_egress")
	seed("external_egress")
	seed("payments.refund.issued")

	policyRepo := policy.NewInMemoryRepository()
	srv := httpadapter.NewRouter(httpadapter.Deps{
		PolicyRepo: policyRepo,
		AuditRepo:  auditRepo,
		IMDARepo:   imda.NewInMemoryRepository(),
		Evaluator:  gatekeeper.NewEvaluator(policyRepo, auditRepo),
	})

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, authedReq(http.MethodGet, "/api/audit?tenant_id="+tenantA+"&action=external_egress", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != 2 {
		t.Fatalf("action filter: Total = %d; want 2 external_egress rows", resp.Total)
	}
	for _, it := range resp.Items {
		if it["action"] != "external_egress" {
			t.Errorf("row action = %v; want external_egress", it["action"])
		}
	}
}
