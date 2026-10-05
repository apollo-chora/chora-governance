// Package httpadapter — Phase-6 BFF-facing handler.
//
// Added so the chora-gateway HTTPUpstream.GetGovernance method has a
// concrete downstream target. Mirrors /api/imda/dashboard but path-parameterizes
// the tenant_id so the BFF can compose `GET {governance}/governance/{id}` per
// Phase 6 contract.
//
// Phase 6 contract:
//
//	GET /governance/{tenant_id} → IMDA dashboard JSON
//
// Response body shape:
//
//	{
//	  "tenant_id": "tenant-a",
//	  "dimensions": [ {assessment_id, dimension, score, ...}, ... ]
//	}
//
// Same shape as /api/imda/dashboard so the BFF can reuse downstream parsing.
//
// This file is intentionally non-overlapping with the existing handler.go /
// imda_handler.go to satisfy the Phase-6 guardrail (NEW files OK; only the
// route-registration is added at the bottom of handler.go with a clear
// "Phase 6:" comment marker).
package httpadapter

import (
	"log"
	"net/http"
	"strings"

	"github.com/apollo-chora/chora-governance/internal/domain/imda"
)

// phase6GovernanceHandler is the GET /governance/{tenant_id} handler.
type phase6GovernanceHandler struct {
	imdas imda.Repository
}

// newPhase6GovernanceHandler constructs the handler.
func newPhase6GovernanceHandler(repo imda.Repository) http.Handler {
	return &phase6GovernanceHandler{imdas: repo}
}

// ServeHTTP implements http.Handler.
func (h *phase6GovernanceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GOV_METHOD_NOT_ALLOWED",
			"only GET is supported on /governance/{tenant_id}")
		return
	}
	tenantID := strings.TrimPrefix(r.URL.Path, "/governance/")
	tenantID = strings.TrimSuffix(tenantID, "/")
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "GOV_TENANT_REQUIRED",
			"tenant_id path parameter is required")
		return
	}
	dash, err := h.imdas.Dashboard(r.Context(), tenantID)
	if err != nil {
		log.Printf("phase6 governance dashboard error: %v", err)
		writeError(w, http.StatusInternalServerError, "GOV_REPO_ERROR", "dashboard failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":  tenantID,
		"dimensions": dash,
	})
}
